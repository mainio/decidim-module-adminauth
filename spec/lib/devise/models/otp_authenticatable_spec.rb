# frozen_string_literal: true

require "spec_helper"

describe Devise::Models::OtpAuthenticatable do
  let(:organization) { create(:organization) }
  let(:user) { create(:user, :admin, :confirmed, :admin_terms_accepted, organization: organization) }
  let(:otp_challenge) { user.generate_otp_session! }

  before do
    user.populate_otp_secrets!
  end

  describe ".find_for_otp_authentication" do
    context "with a valid OTP challenge" do
      it "finds the correct user" do
        expect(user.class.find_for_otp_authentication(otp_challenge)).to eq(user)
      end
    end

    context "with unexisting OTP challenge" do
      let(:otp_challenge) do
        user.generate_otp_session!
        "a" * 128
      end

      it "does not find any user" do
        expect(user.class.find_for_otp_authentication(otp_challenge)).to be_nil
      end
    end
  end

  describe ".otp_challenge_digest" do
    it "generates the correct digest for the user" do
      digest = user.class.otp_challenge_digest(otp_challenge)
      expect(user.otp_session_challenge).to eq(digest)
    end
  end

  describe "#time_based_otp" do
    let(:topt) { user.time_based_otp }
    let(:issuer) { (user.class.otp_issuer || Rails.application.class.module_parent_name).to_s }

    it "creates a ROTP::TOTP instance with the correct details" do
      expect(topt.issuer).to eq(issuer)
      expect(topt.interval).to eq(user.class.otp_authentication_timeout)
      expect(topt.secret).to eq(user.otp_auth_secret)
    end
  end

  describe "#otp_provisioning_uri" do
    let(:issuer) { (user.class.otp_issuer || Rails.application.class.module_parent_name).to_s }
    let(:label) do
      [issuer, user.email].map { |s| ERB::Util.url_encode(s.tr(":", "_")) }.join(":")
    end
    let(:params) do
      {
        secret: user.otp_auth_secret,
        issuer: issuer,
        period: user.class.otp_authentication_timeout
      }
        .compact
        .map { |k, v| "#{k}=#{ERB::Util.url_encode(v)}" }
        .join("&")
    end

    it "generates a valid provisioning URI" do
      expect(user.otp_provisioning_uri).to eq("otpauth://totp/#{label}?#{params}")
    end
  end

  describe "#otp_provisioning_identifier" do
    it "returns the correct idenfier" do
      expect(user.otp_provisioning_identifier).to eq(user.email)
    end
  end

  describe "#clear_otp_session!" do
    before do
      otp_challenge
      user.update!(otp_failed_attempts: 5)
    end

    it "clears the user's OTP session details" do
      expect(user.otp_failed_attempts).to eq(5)
      expect(user.otp_session_challenge).to be_present
      expect(user.otp_challenge_expires_at).to be_present

      user.clear_otp_session!

      expect(user.otp_failed_attempts).to eq(0)
      expect(user.otp_session_challenge).to be_nil
      expect(user.otp_challenge_expires_at).to be_nil
    end
  end

  describe "#populate_otp_secrets!" do
    context "when the secrets are already populated" do
      it "does not repopulate them" do
        original = user.otp_auth_secret
        expect(original).to be_present

        user.populate_otp_secrets!

        expect(user.otp_auth_secret).to eq(original)
      end
    end

    context "when the secrets have not been populated" do
      before do
        user.clear_otp_fields!
      end

      it "populates the secrets" do
        expect(user.otp_auth_secret).to be_nil

        user.populate_otp_secrets!

        expect(user.otp_auth_secret).to be_present
      end
    end
  end

  describe "#clear_otp_fields!" do
    before do
      otp_challenge
      user.update!(otp_failed_attempts: 5)
    end

    it "clears the OTP fields" do
      expect(user.otp_auth_secret).to be_present
      expect(user.otp_failed_attempts).to eq(5)
      expect(user.otp_session_challenge).to be_present
      expect(user.otp_challenge_expires_at).to be_present

      user.clear_otp_fields!

      expect(user.otp_auth_secret).to be_nil
      expect(user.otp_failed_attempts).to eq(0)
      expect(user.otp_session_challenge).to be_nil
      expect(user.otp_challenge_expires_at).to be_nil
    end
  end

  describe "#generate_otp_session!" do
    it "generates the OTP session details" do
      user.generate_otp_session!
    end

    context "when the user already has an existing session" do
      let!(:original_challenge) { otp_challenge }

      before do
        otp_challenge
        user.update!(otp_failed_attempts: 5)
      end

      it "regenerates the session" do
        original_failed_attempts = user.otp_failed_attempts
        original_digest = user.otp_session_challenge
        original_expires_at = user.otp_challenge_expires_at
        expect(original_failed_attempts).to eq(5)
        expect(original_challenge).to be_present
        expect(original_digest).to be_present
        expect(original_expires_at).to be_present

        user.generate_otp_session!

        expect(user.otp_failed_attempts).to eq(0)
        expect(user.otp_session_challenge).not_to eq(original_digest)
        expect(user.otp_challenge_expires_at).to be_present
        expect(user.otp_challenge_expires_at).to be > original_expires_at
      end

      it "returns a correct challenge" do
        challenge = user.generate_otp_session!

        expect(user.class.find_for_otp_authentication(challenge)).to eq(user)
        expect(user.class.find_for_otp_authentication(original_challenge)).to be_nil
      end
    end

    context "when a collision happens" do
      let(:collided_challenge) { "a" * 128 }
      let!(:another_user) do
        create(
          :user,
          :admin,
          :confirmed,
          :admin_terms_accepted,
          organization: organization,
          otp_session_challenge: user.class.otp_challenge_digest(collided_challenge)
        )
      end

      before do
        original_hex = SecureRandom.method(:hex)
        count = 0
        allow(SecureRandom).to receive(:hex) do |length|
          count += 1
          if count > 1
            original_hex.call(length)
          else
            collided_challenge
          end
        end
      end

      it "recalls the method" do
        expect(user).to receive(:generate_otp_session!).twice.and_call_original

        user.generate_otp_session!

        expect(user.otp_session_challenge).not_to eq(another_user.otp_session_challenge)
      end
    end
  end

  describe "#otp_challenge_valid?" do
    context "when the OTP session does not exist" do
      it "returns true" do
        expect(user.otp_challenge_expires_at).to be_nil
        expect(user.otp_challenge_valid?).to be(true)
      end
    end

    context "when the OTP session exists" do
      before do
        otp_challenge
      end

      it "returns true" do
        expect(user.otp_challenge_expires_at).to be_present
        expect(user.otp_challenge_valid?).to be(true)
      end

      context "and the challenge has expired" do
        before do
          travel Devise.otp_authentication_timeout + 1.second
        end

        it "returns false" do
          expect(user.otp_challenge_expires_at).to be_present
          expect(user.otp_challenge_valid?).to be(false)
        end
      end
    end
  end

  describe "#valid_for_otp_authentication?" do
    context "when the user is not persisted" do
      let(:new_user) { Decidim::User.new(organization: organization) }

      context "without a block" do
        it "returns false" do
          expect(new_user.valid_for_otp_authentication?).to be(false)
        end
      end

      context "with a block" do
        it "returns false" do
          expect(new_user.valid_for_otp_authentication? { true }).to be(false)
        end
      end
    end

    context "when the user is not lockable" do
      before do
        modules = user.devise_modules - [:lockable]
        allow(user).to receive(:devise_modules).and_return(modules)
      end

      context "without a block" do
        it "returns true" do
          expect(user.valid_for_otp_authentication?).to be(true)
        end
      end

      context "with a block" do
        it "returns the block result on true" do
          expect(user.valid_for_otp_authentication? { true }).to be(true)
        end

        it "returns the block result on false" do
          expect(user.valid_for_otp_authentication? { false }).to be(false)
        end
      end
    end

    context "when access is not locked" do
      it "returns the block result on true" do
        expect(user.valid_for_otp_authentication? { true }).to be(true)
      end

      it "returns the block result on false" do
        expect(user.valid_for_otp_authentication? { false }).to be(false)
      end
    end

    context "when access is locked" do
      before do
        user.lock_access!
      end

      it "returns false" do
        expect(user.valid_for_otp_authentication? { true }).to be(false)
      end

      it "increments the OTP failed attempts" do
        user.valid_for_otp_authentication? { true }

        expect(user.otp_failed_attempts).to eq(1)
      end
    end

    context "when the last attempt fails" do
      before do
        user.update!(otp_failed_attempts: Devise.otp_maximum_attempts - 1)
      end

      it "returns false" do
        expect(user.valid_for_otp_authentication? { false }).to be(false)
      end

      it "locks the user account" do
        expect(user.access_locked?).to be(false)
        user.valid_for_otp_authentication? { false }
        expect(user.access_locked?).to be(true)
      end
    end
  end

  describe "#valid_otp_token?" do
    before do
      otp_challenge
    end

    context "when the token is valid" do
      let(:token) { user.send(:generate_otp_token) }

      it "returns true" do
        expect(user.valid_otp_token?(token)).to be(true)
      end

      context "when the OTP session does not exist" do
        before do
          user.clear_otp_session!
        end

        it "returns false" do
          expect(user.valid_otp_token?(token)).to be(false)
        end
      end

      context "when the OTP session is expired" do
        before do
          travel Devise.otp_authentication_timeout + 1.second
        end

        it "returns false" do
          expect(user.valid_otp_token?(token)).to be(false)
        end
      end
    end

    context "when the token is invalid" do
      let(:token) { "000000" }

      it "returns false" do
        expect(user.valid_otp_token?(token)).to be(false)
      end
    end

    context "when the token is blank" do
      let(:token) { "" }

      it "returns false" do
        expect(user.valid_otp_token?(token)).to be(false)
      end
    end
  end

  describe "#send_otp_token_instructions" do
    context "when the OTP session does not exist" do
      it "returns nil" do
        expect(user.send_otp_token_instructions).to be_nil
      end

      it "does not send email" do
        expect(ActionMailer::Base.deliveries.count).to eq(0)
        user.send_otp_token_instructions
        expect(ActionMailer::Base.deliveries.count).to eq(0)
      end
    end

    context "when the OTP session exists" do
      before do
        otp_challenge
      end

      it "returns the token" do
        expect(user.send_otp_token_instructions).to match(/\A[0-9]{6}\z/)
      end

      it "sends the OTP instructions email" do
        expect(ActionMailer::Base.deliveries.count).to eq(0)
        user.send_otp_token_instructions
        expect(ActionMailer::Base.deliveries.count).to eq(1)
      end
    end
  end

  describe "#otp_token_resend_possible?" do
    context "when the OTP session does not exist" do
      it "returns false" do
        expect(user.otp_token_resend_possible?).to be(false)
      end
    end

    context "when the OTP session exists" do
      before do
        otp_challenge
      end

      context "when the interval has not yet passed" do
        it "returns the false" do
          expect(user.otp_token_resend_possible?).to be(false)
        end
      end

      context "when the interval has passed" do
        before do
          travel Devise.otp_token_resend_interval + 1.second
        end

        it "returns the true" do
          expect(user.otp_token_resend_possible?).to be(true)
        end
      end

      context "when the session has expired" do
        before do
          travel Devise.otp_authentication_timeout + 1.second
        end

        it "returns the false" do
          expect(user.otp_token_resend_possible?).to be(false)
        end
      end
    end
  end

  describe "#unauthenticated_otp_message" do
    context "when the last OTP attempt is processed" do
      before do
        user.update!(otp_failed_attempts: Devise.otp_maximum_attempts - 1)
      end

      it "returns the correct message key" do
        expect(user.unauthenticated_otp_message).to be(:last_attempt)
      end
    end

    context "when the maximum amount of OTP attempts is exceeded" do
      before do
        user.update!(otp_failed_attempts: Devise.otp_maximum_attempts)
      end

      it "returns the correct message key" do
        expect(user.unauthenticated_otp_message).to be(:locked)
      end
    end

    context "when the account is locked" do
      before do
        user.lock_access!
      end

      it "returns the correct message key" do
        expect(user.unauthenticated_otp_message).to be(:locked)
      end
    end

    context "with any other case" do
      it "returns the correct message key" do
        expect(user.unauthenticated_otp_message).to be(:invalid)
      end
    end
  end
end
