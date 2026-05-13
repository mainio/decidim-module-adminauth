# frozen_string_literal: true

require "decidim/dev"

ENV["ENGINE_ROOT"] = File.dirname(__dir__)

Decidim::Dev.dummy_app_path = File.expand_path(File.join(__dir__, "..", "spec", "decidim_dummy_app"))

require "decidim/dev/test/base_spec_helper"

RSpec::Matchers.define_negated_matcher :not_change, :change
