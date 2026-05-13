# frozen_string_literal: true

require "spec_helper"

describe "OTP authentication" do
  let(:organization) { create(:organization) }
  let(:user) { create(:user, :admin, :confirmed, :admin_terms_accepted, organization: organization) }
  let(:remember_me) { false }

  before do
    switch_to_host(organization.host)
    visit decidim.new_user_session_path
  end

  it "displays the OTP credentials page" do
    initiate_sign_in

    expect(page).to have_css("h1", text: I18n.t("decidim.adminauth.devise.otp_credentials.show.title"))
    expect(page).to have_css("form#otp_new_user")
    expect(page).to have_css("input#user_otp_token")
  end

  context "when signing in with an OTP enabled account" do
    let(:token) do
      email = Nokogiri::HTML(last_email_body)
      email.css("p#otp_token").first.text
    end

    before do
      initiate_sign_in
      expect(page).to have_css("h1", text: I18n.t("decidim.adminauth.devise.otp_credentials.show.title"))
      user.reload
    end

    it "sends the OTP instructions" do
      expect(last_email).not_to be_nil
      expect(last_email.to).to eq([user.email])
      expect(last_email_body).to include(user.send(:generate_otp_token))
    end

    context "with a valid OTP token" do
      before do
        within "form#otp_new_user" do
          fill_in :user_otp_token, with: token
          find("*[type=submit]").click
        end
      end

      it "signs in the user" do
        expect(page).to have_content(I18n.t("devise.sessions.signed_in"))
        expect(page).to have_content(user.name)
      end

      it "clears the OTP session details" do
        expect(page).to have_content(I18n.t("devise.sessions.signed_in"))
        user.reload

        expect(user.otp_failed_attempts).to eq(0)
        expect(user.otp_session_challenge).to be_nil
        expect(user.otp_challenge_expires_at).to be_nil
      end

      it "does not remember the user by default" do
        expect(page).to have_content(I18n.t("devise.sessions.signed_in"))
        expect(page).to have_content(user.name)

        page.driver.browser.manage.delete_cookie("_session_id")

        visit decidim.account_path

        expect(page).to have_content(I18n.t("devise.failure.unauthenticated"))
        expect(page).to have_current_path(decidim.new_user_session_path)
      end

      context "with remember me enabled" do
        let(:remember_me) { true }

        it "signs in the user and remembers the login" do
          expect(page).to have_content(I18n.t("devise.sessions.signed_in"))
          expect(page).to have_content(user.name)

          page.driver.browser.manage.delete_cookie("_session_id")

          visit decidim.account_path

          expect(page).to have_content(user.name)
          expect(page).to have_current_path(decidim.account_path)
        end
      end
    end

    context "with an invalid OTP token" do
      let(:token) { "000000" }

      it "displays the form again with correct error" do
        within "form#otp_new_user" do
          fill_in :user_otp_token, with: token
          find("*[type=submit]").click
        end

        expect(page).to have_content(I18n.t("devise.failure.otp_token_invalid"))
        expect(page).to have_css("h1", text: I18n.t("decidim.adminauth.devise.otp_credentials.show.title"))
      end
    end

    context "when resending the token" do
      let(:interval) { (Devise.otp_token_resend_interval.to_f / 60).ceil }

      it "does not allow resending the token before the resend interval has passed" do
        expect(ActionMailer::Base.deliveries.count).to eq(1)

        find("#resend_code_button").click

        expect(page).to have_content(I18n.t("decidim.adminauth.devise.otp_credentials.resend_too_fast", count: interval))

        expect(ActionMailer::Base.deliveries.count).to eq(1)
      end

      it "resends the token after the interval has passed" do
        expect(ActionMailer::Base.deliveries.count).to eq(1)
        travel interval.minutes + 1.second

        find("#resend_code_button").click

        expect(page).to have_content(I18n.t("decidim.adminauth.devise.otp_credentials.resend_success"))
        expect(ActionMailer::Base.deliveries.count).to eq(2)
      end
    end

    context "when the OTP session has expired" do
      before do
        travel Devise.otp_authentication_timeout + 1.second
      end

      it "redirects the user back to the sign in page" do
        within "form#otp_new_user" do
          fill_in :user_otp_token, with: token
          find("*[type=submit]").click
        end

        expect(page).to have_content(I18n.t("decidim.adminauth.devise.otp_credentials.otp_session_invalid"))
        expect(page).to have_current_path(decidim.new_user_session_path)
      end
    end
  end

  def initiate_sign_in
    within "form#session_new_user" do
      fill_in :session_user_email, with: user.email
      fill_in :session_user_password, with: "decidim123456789"
      check :session_user_remember_me if remember_me
      find("*[type=submit]").click
    end
  end
end
