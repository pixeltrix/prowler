Prowler
=======

[![Build Status][build]][travis] [![Dependency Status][depends]][gemnasium]

This is a plugin/gem for integrating apps with the Prowl iPhone application.

Installation
------------

To install as a plugin from your application root, run:

Rails 2.x:

``` sh
script/plugin install git://github.com/pixeltrix/prowler.git
```

Rails 3.x:

``` sh
script/rails plugin install git://github.com/pixeltrix/prowler.git
```

To install as a gem configure your config.gems or Gemfile:

Rails 2.x:

``` ruby
config.gems 'prowler', :version => '~> 1.2'
```

Rails 3.x:

``` ruby
gem 'prowler', '~> 1.2'
```

Prowler is not limited to Rails apps - it can be used in any situation
where you need to send push notifications to your iPhone.

Configuration
-------------

You should have something like this in config/initializers/prowler.rb.

``` ruby
Prowler.configure do |config|
  config.api_key = 'ffffffffffffffffffffffffffffffffffffffff'
  config.application = 'www.example.com'
end
```

You can test that Prowler is working in your production environment by using
this rake task (from your application root):

``` sh
rake prowler:test
```

If everything is configured properly the task will send a request to
prowlapp.com which will be appear on your iPhone after a short delay.

Usage
-----

To use Prowler within your application just call the notify method, e.g.

``` ruby
Prowler.notify "Event", "Description"
```

If you need to send to multiple accounts from within a single application you
can create an instance of the Prowler class to override the global settings, e.g.

``` ruby
prowler = Prowler.new(:application => 'application', :api_key => 'apikey')
prowler.notify "Event", "Description"
```

If performance is a concern then there is built in support for Delayed::Job.
This can done either on a global basis, e.g.

``` ruby
Prowler.configure do |config|
  config.delayed = true
end
```

or on a individual message basis, e.g.

``` ruby
Prowler.notify "Event", "Description", :delayed => true
```

About
-----

Prowler relies upon the Prowl iPhone application which is advertised as
a Growl notification forwarder from your Mac. However they provide an API
which can be called by a generic script which allows you to use the
application as a general push notification application for your iPhone.

For more about the Prowl application see: http://prowlapp.com/

Contributions
-------------

Bug fixes and new feature patches are welcome. Please provide tests and
documentation wherever possible - without them it is unlikely your patch
will be accepted. If you're fixing a bug then a failing test for the bug
is essential. Once you have completed your patch please open a GitHub
pull request and I will review it and respond as quickly as possible.

Copyright (c) 2011 Andrew White, released under the MIT license

[build]: https://secure.travis-ci.org/pixeltrix/prowler.png
[travis]: http://travis-ci.org/pixeltrix/prowler
[depends]: https://gemnasium.com/pixeltrix/prowler.png?travis
[gemnasium]: https://gemnasium.com/pixeltrix/prowler

