# frozen_string_literal: true

require "spec_helper"

describe Decidim::Adminauth::OtpTokenMailer do
  let(:organization) { create(:organization) }
  let(:user) { create(:user, :admin, :confirmed, :admin_terms_accepted, organization: organization) }

  describe "#otp_token" do
    let(:mail) { described_class.otp_token(user, token) }
    let(:token) { "123456" }

    it "delivers the email to the user" do
      expect(mail.to).to eq([user.email])
    end

    it "displays the user name" do
      expect(mail.body).to include(user.name)
    end

    it "displays the token within the mail body" do
      body = Nokogiri::HTML(mail.body.to_s)
      expect(body.css("p#otp_token").first.text).to eq(token)
    end
  end
end
