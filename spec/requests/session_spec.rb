# frozen_string_literal: true

require "spec_helper"

describe "Session" do
  subject { response.body }

  let(:organization) { create(:organization) }
  let(:correct_password) { "decidim123456789" }

  let(:routes_helper) { Decidim::Core::Engine.routes.url_helpers }
  let(:request_path) { routes_helper.user_session_path }
  let(:headers) { { "HOST" => organization.host } }
  let(:warden) { request.env["warden"] }
  let(:email) { user.email }

  let(:invalid_login_message) do
    keys = [:email].map { |key| Decidim::User.human_attribute_name(key) }
    authentication_keys = keys.join(I18n.t(:"support.array.words_connector"))

    I18n.t("devise.failure.not_found_in_database", authentication_keys: authentication_keys)
  end

  before do
    post(
      request_path,
      params: { user: { email: email, password: password } },
      headers: headers
    )
  end

  shared_examples "OTP required user" do
    context "with correct password" do
      let(:password) { correct_password }

      it "returns the correct status and redirects" do
        expect(response).to have_http_status(:redirect)
        expect(response).to redirect_to(routes_helper.user_otp_credential_path)
        expect(current_user).to be_nil
      end
    end

    context "with incorrect password" do
      let(:password) { "foobar" }

      it "returns the correct status and renders the sign in page" do
        expect(response).to have_http_status(:ok)
        expect(response.body).to include(invalid_login_message)
        expect(current_user).to be_nil
      end
    end
  end

  context "with an admin user" do
    let(:user) { create(:user, :admin, :confirmed, :admin_terms_accepted, organization: organization) }

    it_behaves_like "OTP required user"
  end

  context "with user manager admin user" do
    let(:user) { create(:user, :user_manager, :confirmed, organization: organization) }

    it_behaves_like "OTP required user"
  end

  context "with a process admin user" do
    let(:participatory_space) { create(:participatory_process, :with_steps, organization: organization, skip_injection: true) }
    let(:user) { create(:process_admin, :confirmed, organization: organization, participatory_process: participatory_space) }

    it_behaves_like "OTP required user"
  end

  context "with regular user" do
    let(:user) { create(:user, :confirmed, organization: organization) }

    context "with correct password" do
      let(:password) { correct_password }

      it "returns the correct status and redirects" do
        expect(response).to have_http_status(:redirect)
        expect(response).to redirect_to("/")
        expect(current_user).to eq(user)
      end
    end

    context "with incorrect password" do
      let(:password) { "foobar" }

      it "returns the correct status and renders the sign in page" do
        expect(response).to have_http_status(:ok)
        expect(response.body).to include(invalid_login_message)
        expect(current_user).to be_nil
      end
    end
  end

  context "with unexisting user" do
    let(:email) { "unexisting@example.org" }
    let(:password) { "foobar" }

    it "returns the correct status and renders the sign in page" do
      expect(response).to have_http_status(:ok)
      expect(response.body).to include(invalid_login_message)
      expect(current_user).to be_nil
    end
  end

  def current_user
    warden.user(:user)
  end
end
