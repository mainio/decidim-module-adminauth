# frozen_string_literal: true

require "devise/strategies/authenticatable"

module Devise
  module Strategies
    # Default strategy for signing in a user, based on their email and password in the database.
    #
    # Overrides the default Devise DatabaseAuthenticatable module in order to take control of the login flow and
    # to require admin accounts to provide the OTP challenge before authenticating them.
    #
    # Based on the devise-otp gem (MIT).
    class DatabaseAuthenticatable < Authenticatable
      def authenticate!
        resource = password.present? && mapping.to.find_for_database_authentication(authentication_hash)
        hashed = false

        if validate(resource) { hashed = true; resource.valid_password?(password) } # rubocop:disable Style/Semicolon
          if otp_challenge_required_on?(resource)
            session = env["rack.session"]

            # Redirect to challenge
            resource.populate_otp_secrets!
            challenge = resource.generate_otp_session!
            resource.send_otp_token_instructions

            session[:otp_session] = { challenge: challenge, remember_me: remember_me? }

            redirect!(otp_challenge_path)
          else
            # Sign in user as usual
            remember_me(resource)
            resource.after_database_authentication
            success!(resource)
          end
        end

        # In paranoid mode, hash the password even when a resource doesn't exist for the given authentication key.
        # This is necessary to prevent enumeration attacks - e.g. the request is faster when a resource doesn't
        # exist in the database if the password hashing algorithm is not called.
        mapping.to.new.password = password if !hashed && Devise.paranoid
        unless resource
          Devise.paranoid ? fail(:invalid) : fail(:not_found_in_database) # rubocop:disable Style/SignalException
        end
      end

      private

      # Define which users are required to perform the OTP challenge.
      def otp_challenge_required_on?(resource)
        return false unless resource.is_a?(Decidim::User)
        return true if resource.admin? || resource.role?("user_manager")

        # Check if the user has access to admin panel, e.g. participatory space
        # admin users.
        Decidim::Admin::Permissions.new(
          resource,
          Decidim::PermissionAction.new(scope: :admin, action: :read, subject: :admin_dashboard)
        ).permissions.allowed?
      end

      def otp_challenge_path
        Decidim::Core::Engine.routes.url_helpers.public_send("#{mapping.singular}_otp_credential_path")
      end
    end
  end
end

Warden::Strategies.add(:database_authenticatable, Devise::Strategies::DatabaseAuthenticatable)
