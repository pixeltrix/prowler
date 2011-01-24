require 'test/unit'
require 'rubygems'
require 'mocha'
require 'shoulda'
require File.join(File.dirname(__FILE__), "..", "lib", "prowler")

RAILS_ROOT = File.dirname(__FILE__)

class ProwlerTest < Test::Unit::TestCase
  context "Prowler configuration" do
    setup do
      Prowler.reset_configuration
      Prowler.send_notifications = false
    end

    should "be done with a block" do
      Prowler.configure do |config|
        config.api_key = "apikey"
        config.application = "application"
      end

      assert_equal "apikey",      Prowler.api_key
      assert_equal "application", Prowler.application
    end

    should "not set a default application" do
      assert_equal nil, Prowler.application
    end

    should "not set a default API key" do
      assert_equal nil, Prowler.api_key
    end

    should "override class configuration when using an instance" do
      prowler = Prowler.new("apikey2", "application2")
      assert_equal "apikey2",      prowler.api_key
      assert_equal "application2", prowler.application
    end
  end

  context "Sending a notification" do
    setup do
      Prowler.reset_configuration
      Prowler.configure do |config|
        config.api_key = "apikey"
        config.application = "Application Name"
      end
      Prowler.send_notifications = false
    end

    should "raise an exception if API key not configured" do
      Prowler.reset_configuration
      assert_raises Prowler::ConfigurationError do
        Prowler.notify("Event", "Description", Prowler::Priority::NORMAL)
      end

      prowler = Prowler.new(nil, nil)
      assert_raises Prowler::ConfigurationError do
        prowler.notify("Event", "Description", Prowler::Priority::NORMAL)
      end
    end

    should "raise an exception if application not configured" do
      Prowler.reset_configuration
      Prowler.configure do |config|
        config.api_key = "apikey"
      end
      assert_raises Prowler::ConfigurationError do
        Prowler.notify("Event", "Description", Prowler::Priority::NORMAL)
      end

      prowler = Prowler.new("apikey", nil)
      assert_raises Prowler::ConfigurationError do
        prowler.notify("Event", "Description", Prowler::Priority::NORMAL)
      end
    end

    should "verify SSL certificates by default" do
      Net::HTTP.any_instance.expects(:use_ssl=).with(true)
      Net::HTTP.any_instance.expects(:verify_mode=).with(OpenSSL::SSL::VERIFY_PEER)
      Net::HTTP.any_instance.expects(:ca_file=).with(File.join(RAILS_ROOT, "config", "cacert.pem"))
      Prowler.notify("Event Name", "Message Text", Prowler::Priority::NORMAL)
    end

    should "not verify SSL certificates if verification is turned off" do
      Prowler.configure do |config|
        config.verify_certificate = false
      end
      Net::HTTP.any_instance.expects(:use_ssl=).with(true)
      Net::HTTP.any_instance.expects(:verify_mode=).with(OpenSSL::SSL::VERIFY_NONE)
      Prowler.notify("Event Name", "Message Text", Prowler::Priority::NORMAL)
    end

    should "not send notifications if send_notifications is false" do
      Net::HTTP.any_instance.expects(:request).never
      Prowler.notify("Event Name", "Message Text", Prowler::Priority::NORMAL)
    end

    should "send multiple API keys if configured" do
      Prowler.configure do |config|
        config.api_key = %w(apikey1 apikey2)
      end
      Net::HTTP::Post.any_instance.expects(:form_data=).with({
        :apikey => "apikey1,apikey2",
        :application => "Application Name",
        :event => "Event Name",
        :description => "Message Text",
        :priority => Prowler::Priority::NORMAL
      })
      Prowler.notify("Event Name", "Message Text", Prowler::Priority::NORMAL)
    end
  end

  context "Verifying an API key" do
    setup do
      Prowler.reset_configuration
      Prowler.configure do |config|
        config.api_key = "apikey"
        config.application = "Application Name"
      end
      Prowler.send_notifications = false
    end

    should "raise an exception if API key not configured" do
      Prowler.reset_configuration
      assert_raises Prowler::ConfigurationError do
        Prowler.verify
      end

      prowler = Prowler.new(nil, nil)
      assert_raises Prowler::ConfigurationError do
        prowler.verify
      end
    end

    should "only verify the first API key" do
      Prowler.configure do |config|
        config.api_key = %w(apikey1 apikey2)
      end
      Net::HTTP::Get.expects(:new).with("/publicapi/verify?apikey=apikey1", { 'User-Agent' => Prowler::USER_AGENT }).once
      Prowler.verify
    end

    should "verify SSL certificates by default" do
      Net::HTTP.any_instance.expects(:use_ssl=).with(true)
      Net::HTTP.any_instance.expects(:verify_mode=).with(OpenSSL::SSL::VERIFY_PEER)
      Net::HTTP.any_instance.expects(:ca_file=).with(File.join(RAILS_ROOT, "config", "cacert.pem"))
      Prowler.verify
    end

    should "not verify SSL certificates if verification is turned off" do
      Prowler.configure do |config|
        config.verify_certificate = false
      end
      Net::HTTP.any_instance.expects(:use_ssl=).with(true)
      Net::HTTP.any_instance.expects(:verify_mode=).with(OpenSSL::SSL::VERIFY_NONE)
      Prowler.verify
    end

    should "not send notifications if send_notifications is false" do
      Net::HTTP.any_instance.expects(:request).never
      Prowler.verify
    end
  end
end
