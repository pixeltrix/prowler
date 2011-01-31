module Prowler
  class Error < StandardError
    # The status code returned by the Prowl API
    attr_reader :status

    # The error message returned by the Prowl API
    attr_reader :message

    def initialize(document) #:nodoc:
      error = document.elements["prowl/error"]

      @status = error.attributes["code"].to_i
      @message = "Prowl Failure: #{error.text}"
    end
  end

  class Success
    # The status code returned by the Prowl API - always 200
    attr_reader :status

    # The number of remaining requests until the counter is reset
    attr_reader :remaining

    # The time when the request counter will be reset
    attr_reader :reset_date

    def initialize(document) #:nodoc:
      success = document.elements["prowl/success"]

      @status = success.attributes["code"].to_i
      @remaining = success.attributes["remaining"].to_i
      @reset_date = Time.at(success.attributes["resetdate"].to_i)
    end
  end

  class Token < Success
    # The token returned by the Prowl API to use in a retrieve_api_key request
    attr_reader :token

    # The url to redirect a user to for access confirmation
    attr_reader :url

    def initialize(document) #:nodoc:
      super(document)

      retrieve = document.elements["prowl/retrieve"]
      @token = retrieve.attributes["token"]
      @url = retrieve.attributes["url"]
    end
  end

  class ApiKey < Success
    # The API key returned by the Prowl API
    attr_reader :api_key

    def initialize(document) #:nodoc:
      super(document)

      retrieve = document.elements["prowl/retrieve"]
      @api_key = retrieve.attributes["apikey"]
    end
  end
end