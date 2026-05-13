# frozen_string_literal: true

require "spec_helper"

describe "Regular user authentication" do
  let(:organization) { create(:organization) }
  let(:user) { create(:user, :confirmed, organization: organization) }
  let(:password) { "decidim123456789" }
  let(:remember_me) { false }

  before do
    switch_to_host(organization.host)
    visit decidim.new_user_session_path
  end

  context "when signing in with an account that does not have OTP enabled" do
    before do
      initiate_sign_in
    end

    context "with correct credentials" do
      it "signs in the user normally" do
        expect(page).to have_content(I18n.t("devise.sessions.signed_in"))
        expect(page).to have_content(user.name)
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

    context "with incorrect credentials" do
      let(:password) { "foobar" }

      shared_examples "invalid login attempt" do
        it "displays the form again with correct error" do
          keys = [:email].map { |key| user.class.human_attribute_name(key) }
          authentication_keys = keys.join(I18n.t(:"support.array.words_connector"))

          expect(page).to have_content(I18n.t("devise.failure.not_found_in_database", authentication_keys: authentication_keys))
          expect(page).not_to have_content(user.name)
          expect(page).to have_current_path(decidim.new_user_session_path)
        end
      end

      context "with Devise.paranoid set to false" do
        before do
          allow(Devise).to receive(:paranoid).and_return(false)
        end

        it_behaves_like "invalid login attempt"
      end

      context "with Devise.paranoid set to true" do
        before do
          allow(Devise).to receive(:paranoid).and_return(true)
        end

        it_behaves_like "invalid login attempt"
      end
    end
  end

  def initiate_sign_in
    within "form#session_new_user" do
      fill_in :session_user_email, with: user.email
      fill_in :session_user_password, with: password
      check :session_user_remember_me if remember_me
      find("*[type=submit]").click
    end
  end
end
