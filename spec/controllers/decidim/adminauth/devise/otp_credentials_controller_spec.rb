# frozen_string_literal: true

require "spec_helper"

describe Decidim::Adminauth::Devise::OtpCredentialsController do
  routes { Decidim::Core::Engine.routes }

  let(:urls) { Decidim::Core::Engine.routes.url_helpers }
  let(:organization) { create(:organization) }
  let!(:user) { create(:user, :admin, :confirmed, :admin_terms_accepted, organization: organization) }
  let(:otp_session) { { challenge: otp_challenge, remember_me: remember_me } }
  let(:otp_challenge) do
    user.populate_otp_secrets!
    user.generate_otp_session!
  end
  let(:remember_me) { false }

  before do
    request.env["devise.mapping"] = Devise.mappings[:user]
    request.env["decidim.current_organization"] = organization

    controller.session[:otp_session] = otp_session if otp_session
  end

  shared_examples "invalid OTP session" do
    shared_examples "invalid OTP session redirect" do
      it "redirects to sign in" do
        action

        expect(response).to redirect_to(urls.new_user_session_path)
        expect(flash[:alert]).to eq(I18n.t("decidim.adminauth.devise.otp_credentials.otp_session_invalid"))
        expect(warden.authenticated?(:user)).to be(false)
      end
    end

    context "when the challenge is incorrect" do
      let(:otp_challenge) do
        user.populate_otp_secrets!
        user.generate_otp_session!

        "foobar"
      end

      it_behaves_like "invalid OTP session redirect"
    end

    context "when the OTP session has not been initiated" do
      let(:otp_challenge) do
        user.populate_otp_secrets!

        "foobar"
      end

      it_behaves_like "invalid OTP session redirect"
    end

    context "when the OTP secrets and session have not been initiated" do
      let(:otp_challenge) { "foobar" }

      it_behaves_like "invalid OTP session redirect"
    end

    context "when the challenge is expired" do
      before do
        travel Devise.otp_authentication_timeout + 1.second
      end

      it_behaves_like "invalid OTP session redirect"
    end
  end

  describe "GET show" do
    it_behaves_like "invalid OTP session" do
      let(:action) { get :show }
    end

    context "when the challenge is correct" do
      it "redirects" do
        get :show

        expect(response).to render_template(:show)
      end
    end
  end

  describe "POST create" do
    it_behaves_like "invalid OTP session" do
      let(:action) { post :create }
    end

    context "when resending is not yet possible" do
      it "redirects the user back to the show action with correct error" do
        post :create

        expect(response).to redirect_to(urls.user_otp_credential_path)

        interval = (Devise.otp_token_resend_interval.to_f / 60).ceil
        expect(flash[:alert]).to eq(I18n.t("decidim.adminauth.devise.otp_credentials.resend_too_fast", count: interval))
      end

      it "does not update the OTP session" do
        expect do
          post :create
          user.reload
        end.not_to change(user, :otp_session_challenge)
      end

      it "does not send email" do
        post :create

        expect(last_email).to be_nil
      end
    end

    context "when resending is possible" do
      before do
        travel Devise.otp_token_resend_interval + 1.second
      end

      it "redirects the user back to the show action with the correct message" do
        post :create

        expect(response).to redirect_to(urls.user_otp_credential_path)
        expect(flash[:notice]).to eq(I18n.t("decidim.adminauth.devise.otp_credentials.resend_success"))
      end

      it "updates the OTP session" do
        expect do
          post :create
          user.reload
        end.to change(user, :otp_session_challenge)
      end

      it "regenerates the code and delivers it to the user" do
        post :create

        expect(last_email).not_to be_nil

        # The reload is needed as the action updates the expires at time when
        # the OTP session is re-generated.
        user.reload
        correct_token = user.send(:generate_otp_token)

        expect(last_email.to).to eq([user.email])
        expect(last_email_body).to include(correct_token)
      end
    end
  end

  describe "PUT update" do
    let(:token) { user.send_otp_token_instructions }

    it_behaves_like "invalid OTP session" do
      let(:action) { put :update, params: { user: { otp_token: token } } }
    end

    context "when the OTP token is valid" do
      before do
        user.update!(otp_failed_attempts: 2)
      end

      it "signs in the user and redirects" do
        put :update, params: { user: { otp_token: token } }

        expect(response).to redirect_to("/")
        expect(flash[:notice]).to eq(I18n.t("devise.sessions.signed_in"))
        expect(warden.user(:user)).to eq(user)
      end

      it "clears the OTP session" do
        put :update, params: { user: { otp_token: token } }

        expect(warden.user(:user)).to eq(user)
        expect(controller.session[:otp_session]).to be_nil

        user.reload
        expect(user.otp_failed_attempts).to eq(0)
        expect(user.otp_session_challenge).to be_nil
        expect(user.otp_challenge_expires_at).to be_nil
      end

      context "when the user has an after sign in path" do
        before do
          controller.session[:user_return_to] = "/pages"
        end

        it "redirects to the correct location" do
          put :update, params: { user: { otp_token: token } }

          expect(response).to redirect_to("/pages")
          expect(flash[:notice]).to eq(I18n.t("devise.sessions.signed_in"))
          expect(warden.user(:user)).to eq(user)
        end
      end

      context "when the user was set to be remembered" do
        let(:remember_me) { true }

        it "sets the remember cookie for the user" do
          # Note that the remember_me value needs to be passed within the
          # params_auth_hash in order for it to work through Devise. This is
          # handled through the OTP token submission form.
          put :update, params: { user: { otp_token: token, remember_me: "true" } }

          expect(warden.user(:user)).to eq(user)

          expect(response.cookies["remember_user_token"]).to be_present

          jar = ActionDispatch::Cookies::CookieJar.build(request, response.cookies)
          _, token, generated_at = jar.signed["remember_user_token"]

          user.reload
          expect(user.remember_me?(token, generated_at)).to be(true)
        end
      end
    end

    context "when the OTP token is blank" do
      let(:token) { "" }

      it "returns the correct status code and renders the correct error" do
        put :update, params: { user: { otp_token: token } }

        expect(response).to have_http_status(:ok)
        expect(response).to render_template(:show)
        expect(flash[:alert]).to eq(I18n.t("devise.failure.otp_token_blank"))
        expect(warden.authenticated?(:user)).to be(false)
      end
    end

    context "when the OTP token is invalid" do
      let(:token) { "000000" }

      it "returns the correct status code and renders the correct error" do
        put :update, params: { user: { otp_token: token } }

        expect(response).to have_http_status(:ok)
        expect(response).to render_template(:show)
        expect(flash[:alert]).to eq(I18n.t("devise.failure.otp_token_invalid"))
        expect(warden.authenticated?(:user)).to be(false)
      end

      context "and the user has the last OTP attempt" do
        before do
          user.update!(otp_failed_attempts: Devise.otp_maximum_attempts - 2)
        end

        it "returns the correct status code and renders the correct error" do
          put :update, params: { user: { otp_token: token } }

          expect(response).to have_http_status(:ok)
          expect(response).to render_template(:show)
          expect(flash[:alert]).to eq(I18n.t("devise.failure.last_attempt"))
          expect(warden.authenticated?(:user)).to be(false)
        end
      end

      context "and the user's account is locked during the last attempt" do
        before do
          user.update!(otp_failed_attempts: Devise.otp_maximum_attempts - 1)
        end

        it "returns the correct status code and redirects to the sign in page" do
          put :update, params: { user: { otp_token: token } }

          expect(response).to redirect_to(urls.new_user_session_path)
          expect(flash[:alert]).to eq(I18n.t("devise.failure.locked"))
          expect(warden.authenticated?(:user)).to be(false)
        end
      end
    end
  end
end
