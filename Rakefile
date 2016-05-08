# Graphene project Rakefile
#
# Copyright (C) 2015-2017 Alex Chien <alexchien97@gmail.com>
# Licensed under the Apache License, Version 2.0

require "rspec/core/rake_task"

desc "Run all specs"
RSpec::Core::RakeTask.new(:spec) do |spec|
  spec.pattern = 'specs/**/*_spec.rb'
  spec.rspec_opts = ['--backtrace']
end

desc "run javascript tests"
task :test_js do
  ENV['RUBYLIB'] = "lib"
  puts "Launching js test runner"
  system("tests/js/runner")
end

desc "run integration/stress tests"
task :integration do
  ENV['RUBYLIB'] = "lib"
  puts "Launching integration test runner"
  system("tests/integration/runner")
end

begin
  require "yard"
  YARD::Rake::YardocTask.new do |t|
    #t.files   = ['lib/**/*.rb', OTHER_PATHS]   # optional
    #t.options = ['--any', '--extra', '--opts'] # optional
  end
rescue LoadError
end

desc "build the graphene gem"
task :build do
  system "gem build graphene.gemspec"
end
