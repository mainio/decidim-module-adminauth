# frozen_string_literal: true

module Decidim
  module Adminauth
    module Devise
      class OtpCredentialsController < DeviseController
        include Decidim::DeviseControllers

        helper OtpRoutesHelper

        delegate :user_otp_credential_path, to: :core_url_helpers

        helper_method :user_otp_credential_path, :remember_me?

        prepend_before_action :require_no_authentication, only: [:show, :create, :update]
        prepend_before_action :allow_params_authentication!, only: :update

        before_action :set_challenge, only: [:show, :create, :update]
        before_action :set_resource, only: [:show, :create]

        def show
          render :show
        end

        # Re-sends the OTP token to the user. This is in case the email delivery
        # failed or the user did not receive the message for some reason.
        def create
          if resource.otp_token_resend_possible?
            @challenge = resource.generate_otp_session!
            resource.send_otp_token_instructions
            session[:otp_session][:challenge] = @challenge

            set_flash_message! :notice, :resend_success
          else
            interval = (resource.class.otp_token_resend_interval.to_f / 60).ceil
            set_flash_message! :alert, :resend_too_fast, count: interval
          end

          redirect_to user_otp_credential_path
        end

        # Signs in the resource, if the OTP token is valid and the user has a
        # valid challenge.
        def update
          # Warden handles the authentication already before this action is
          # called. At this stage, the user is already authenticated if the OTP
          # authentication strategy was successful.
          #
          # Note that the user's challenge has been already cleared after a
          # succesful authentication, so the resource has to be fetched through
          # warden.
          if warden.authenticated?(resource_name)
            self.resource = warden.user(resource_name)
            session.delete(:otp_session)
            set_flash_message! :notice, :signed_in, scope: "devise.sessions"
            respond_with resource, location: after_sign_in_path_for(resource)
          else
            set_resource
            handle_warden_failure if resource
          end
        end

        private

        def remember_me?
          otp_session[:remember_me] == true
        end

        # This handles the warden failures during the show action as this action
        # is recalled on warden failures. Otherwise in the specific failure
        # situations, the user would remain on the OTP token page even if their
        # account would be locked.
        def handle_warden_failure
          # This would indicate that warden was not run properly in case there
          # is not result status available.
          return redirect_to new_session_path(resource_name) unless warden.result == :failure

          # Failed login attempts will recall the show method which is why this
          # check is done at this stage.
          case warden.message
          when :locked
            set_flash_message! :alert, :locked, scope: "devise.failure"
            redirect_to new_session_path(resource_name)
          else
            set_flash_message! :alert, warden.message, scope: "devise.failure", now: true
            render :show, status: ::Devise.responder.error_status
          end
        end

        def set_challenge
          @challenge = otp_session[:challenge]

          redirect_to decidim.root_path if @challenge.blank?
        end

        def set_resource
          self.resource = resource_class.find_for_otp_authentication(@challenge)

          if resource.blank?
            set_flash_message! :alert, :otp_session_invalid
            redirect_to new_session_path(resource_name)
          end
        end

        def otp_session
          @otp_session ||= (session[:otp_session] || {}).with_indifferent_access
        end

        def core_url_helpers
          Decidim::Core::Engine.routes.url_helpers
        end

        def translation_scope
          "decidim.adminauth.devise.otp_credentials"
        end
      end
    end
  end
end
