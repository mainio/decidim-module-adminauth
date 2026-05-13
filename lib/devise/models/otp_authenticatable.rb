# frozen_string_literal: true

require "rotp"
require "openssl"
require "devise/hooks/otp_authenticatable"
require "devise/strategies/otp_authenticatable"

module Devise::Models
  # Based on the devise-otp gem (MIT).
  module OtpAuthenticatable
    extend ActiveSupport::Concern

    include Decidim::RecordEncryptor

    included do
      # The otp_auth_secret is encrypted because we need to be able to read this
      # value at the server in order to generate the OTP codes. This is a
      # user-specific secret that is generated during the OTP enrollment phase
      # which currently happens automatically during the first OTP enforced
      # login.
      encrypt_attribute :otp_auth_secret, type: :string

      scope :with_valid_otp_challenge, ->(time) { where("otp_challenge_expires_at > ?", time) }
    end

    module ClassMethods
      ::Devise::Models.config(
        self,
        :otp_authentication_timeout,
        :otp_issuer,
        :otp_maximum_attempts,
        :otp_token_resend_interval
      )

      def find_for_otp_authentication(challenge)
        digest = otp_challenge_digest(challenge)
        with_valid_otp_challenge(Time.current).where(otp_session_challenge: digest).first
      end

      # Uses the same digest algorithm as Devise uses for the expiring user
      # tokens. This also makes the keys specific to the instance thanks to the
      # key generator that uses the instance specific secret from Devise.
      #
      # Digesting the value in the database protects the raw challenge values in
      # case the stored digested values are leaked from the database.
      def otp_challenge_digest(raw_challenge)
        @otp_key_generator ||= begin
          secret_key = Devise.secret_key
          ActiveSupport::CachingKeyGenerator.new(ActiveSupport::KeyGenerator.new(secret_key))
        end

        key = @otp_key_generator.generate_key("#{name}#otp_session_challenge")
        OpenSSL::HMAC.hexdigest("SHA256", key, raw_challenge)
      end
    end

    def time_based_otp
      @time_based_otp ||= ROTP::TOTP.new(
        otp_auth_secret,
        issuer: otp_issuer,
        interval: self.class.otp_authentication_timeout
      )
    end

    def otp_issuer
      (self.class.otp_issuer || Rails.application.class.module_parent_name).to_s
    end

    def otp_provisioning_uri
      time_based_otp.provisioning_uri(otp_provisioning_identifier)
    end

    def otp_provisioning_identifier
      email
    end

    def clear_otp_session!
      update!(
        otp_failed_attempts: 0,
        otp_session_challenge: nil,
        otp_challenge_expires_at: nil
      )
    end

    def populate_otp_secrets!
      if otp_auth_secret.blank?
        generate_otp_auth_secret
        save!
      end
    end

    def clear_otp_fields!
      @time_based_otp = nil

      update!(
        otp_auth_secret: nil,
        otp_failed_attempts: 0,
        otp_session_challenge: nil,
        otp_challenge_expires_at: nil
      )
    end

    def generate_otp_session!
      raw_challenge = SecureRandom.hex(128)
      digest = self.class.otp_challenge_digest(raw_challenge)

      update!(
        otp_failed_attempts: 0,
        otp_session_challenge: digest,
        otp_challenge_expires_at: Time.current + self.class.otp_authentication_timeout
      )

      # The value is stored in an encrypted session cookie for the user, so the
      # users cannot read or modify these values themselves.
      raw_challenge
    rescue ActiveRecord::RecordNotUnique
      # Retry in case there is a collision with the challenge digest value. This
      # may happen in the extremely rare case there is a collision for the
      # challenge digest with another user (one in every 2^128 for a 50%
      # chance). The unique index on the column ensures no user could hijack
      # another user's OTP session in case the collision happens.
      generate_otp_session!
    end

    def otp_challenge_valid?
      (otp_challenge_expires_at.nil? || otp_challenge_expires_at > Time.current)
    end

    # Similar to valid_for_authentication? from Devise::Models::Lockable for
    # verifying whether a user is allowed to sign in or not. Checks if the
    # account is locked and allows authentication only if it is not.
    def valid_for_otp_authentication?(&block)
      return false unless persisted?
      return execute_otp_authentication_validity_block(&block) unless devise_modules.include?(:lockable)

      # Unlock the user if the lock is expired, no matter if the user can login
      # or not (wrong OTP token).
      unlock_access! if lock_expired?

      if execute_otp_authentication_validity_block(&block) && !access_locked?
        true
      else
        increment_otp_failed_attempts
        lock_access! if otp_attempts_exceeded? && !access_locked?
        false
      end
    end

    def valid_otp_token?(token)
      if validate_otp_time_token(token)
        true
      else
        false
      end
    end

    def send_otp_token_instructions
      # In case the token generation fails, the OTP secrets and/or the OTP
      # session have not been initiated.
      token = generate_otp_token
      return unless token

      message = Decidim::Adminauth::OtpTokenMailer.otp_token(self, token)
      message.deliver_now

      token
    end

    def otp_token_resend_possible?
      return false if otp_challenge_expires_at.blank?
      return false unless otp_challenge_valid?

      issued_at = otp_challenge_expires_at - self.class.otp_authentication_timeout
      Time.current > issued_at + self.class.otp_token_resend_interval
    end

    # The Device paranoid configuration can be omitted for the failed OTP logins
    # because when the user is shown the OTP screen, they are already
    # authenticated with their email and password. Therefore, the paranoid
    # configuration is not applicable to this case.
    def unauthenticated_otp_message
      if devise_modules.include?(:lockable)
        return :last_attempt if otp_last_attempt?
        return :locked if access_locked? || otp_attempts_exceeded?
      end

      :invalid
    end

    private

    def execute_otp_authentication_validity_block
      return true unless block_given?

      yield
    end

    def otp_attempts_exceeded?
      otp_failed_attempts >= self.class.otp_maximum_attempts
    end

    def otp_last_attempt?
      otp_failed_attempts == self.class.otp_maximum_attempts - 1
    end

    def increment_otp_failed_attempts
      # Increment the counter similarly as in Devise::Models::Loackable for
      # concurrency support.
      self.class.increment_counter(:otp_failed_attempts, id) # rubocop:disable Rails/SkipsModelValidations
      reload
    end

    def validate_otp_time_token(token)
      return false if token.blank?
      return false if otp_challenge_expires_at.blank?
      return false if otp_challenge_expires_at <= Time.current

      verified_token_time = time_based_otp.verify(
        token,
        at: otp_challenge_expires_at
      )
      verified_token_time.present?
    end

    # Generates a valid expiring OTP token to deliver to the user's email. The
    # time of the OTP code is "locked" at the OTP challenge expiration time
    # because otherwise the tokens might expire during the login window.
    def generate_otp_token
      return if otp_challenge_expires_at.blank?

      time_based_otp.at(otp_challenge_expires_at)
    end

    def generate_otp_auth_secret
      self.otp_auth_secret = ROTP::Base32.random_base32
    end
  end
end
