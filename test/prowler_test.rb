require 'test/unit'
require 'rubygems'
require 'mocha'
require 'shoulda'
require File.join(File.dirname(__FILE__), "..", "lib", "prowler")

class ProwlerTest < Test::Unit::TestCase
  context "Prowler configuration" do
    setup do
      Prowler.reset_configuration
      Prowler.send_notifications = false
    end

    should "be done with a block" do
      Prowler.configure do |config|
        config.host = "prowler"
        config.port = 666
        config.secure = false
        config.application = "application"
        config.username = "username"
        config.password = "password"
      end

      assert_equal "prowler",     Prowler.host
      assert_equal 666,           Prowler.port
      assert_equal false,         Prowler.secure
      assert_equal "application", Prowler.application
      assert_equal "username",    Prowler.username
      assert_equal "password",    Prowler.password
    end

    should "set a default host" do
      assert_equal "prowl.weks.net", Prowler.host
    end

    should "set a default port" do
      assert_equal 443, Prowler.port
    end

    should "default to secure" do
      assert_equal true, Prowler.secure
    end

    should "not set a default application" do
      assert_equal nil, Prowler.application
    end

    should "not set a default username" do
      assert_equal nil, Prowler.username
    end

    should "not set a default password" do
      assert_equal nil, Prowler.password
    end

    should "raise an exception if not configured" do
      assert_raises RuntimeError do
        Prowler.notify "Event", "Description"
      end
    end
  end

  context "Sending a notification" do
    setup do
      Prowler.reset_configuration
      Prowler.configure do |config|
        config.application = "Application Name"
        config.username = "username"
        config.password = "password"
      end
      Prowler.send_notifications = false
    end

    should "encode the url parameters" do
      expectation = Prowler.expects(:path)
      expectation.with("Application%20Name", "Event%20Name", "Message%20Text")
      expectation.returns("/api/add_notification.php?application=Application%20Name&event=Event%20Name&description=Message%20Text")
      Prowler.notify("Event Name", "Message Text")
    end

    should "not verify SSL certificates" do
      Net::HTTP.any_instance.expects(:use_ssl=).with(true)
      Net::HTTP.any_instance.expects(:verify_mode=).with(OpenSSL::SSL::VERIFY_NONE)
      Prowler.notify("Event Name", "Message Text")
    end

    should "use HTTP Basic Authentication" do
      Net::HTTP::Get.any_instance.expects(:basic_auth).with(Prowler.username, Prowler.password)
      Prowler.notify("Event Name", "Message Text")
    end

    should "not send notifications if send_notifications is false" do
      Net::HTTP.any_instance.expects(:request).never
      Prowler.notify("Event Name", "Message Text")
    end
  end
end
