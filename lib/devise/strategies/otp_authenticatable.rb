# frozen_string_literal: true

require "devise/strategies/authenticatable"

module Devise
  module Strategies
    # Login users with the OTP token. This strategy is responsible for handling
    # the OTP logins after the user has successfully authenticated themselves
    # through the password login.
    class OtpAuthenticatable < Authenticatable
      # Indicates a valid strategy, meaning this strategy will be run to perform
      # the authentication process.
      def valid?
        @otp_session = nil

        params_authenticatable? && valid_params_request? && valid_params? &&
          valid_auth_params? && valid_otp_session?
      end

      def authenticate!
        challenge = otp_session[:challenge]
        resource = challenge.present? && mapping.to.find_for_otp_authentication(challenge)
        return fail!(:invalid) unless resource

        token = params_auth_hash["otp_token"]

        # The valid_for_otp_authentication? method must be executed with the
        # validation result as a block (as the DatabaseAuthenticatable strategy
        # does via the validate method of the Authenticatable strategy). If
        # true, and the account is not locked, then authentication will proceed
        # as normal. If false, then the valid_for_otp_authentication? method
        # will increment the OTP failed attempts and lock the account similarly
        # to Devise::Models::Lockable after the maximum amount of failed OTP
        # attempts is reached.
        if resource.valid_for_otp_authentication? { resource.valid_otp_token?(token) }
          remember_me(resource) if resource.devise_modules.include?(:rememberable) && otp_session[:remember_me] == true
          resource.after_database_authentication
          success!(resource)
        else
          message = failed_message_for(resource, token)
          fail!(message)
        end
      end

      private

      def failed_message_for(resource, token)
        message = resource.unauthenticated_otp_message
        return message if message == :locked

        if message == :last_attempt
          message
        elsif token.blank?
          :otp_token_blank
        else
          :otp_token_invalid
        end
      end

      def otp_session
        @otp_session ||= session[:otp_session]&.with_indifferent_access if valid_session_class?
      end

      def session
        env["rack.session"]
      end

      def valid_session_class?
        session.is_a?(ActionDispatch::Request::Session) || session.is_a?(ActionController::TestSession)
      end

      def valid_otp_session?
        otp_session.is_a?(Hash)
      end

      def valid_auth_params?
        params_auth_hash.has_key?("otp_token")
      end
    end
  end
end

Warden::Strategies.add(:otp_authenticatable, Devise::Strategies::OtpAuthenticatable)
