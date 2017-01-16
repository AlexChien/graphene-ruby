# -*- encoding: utf-8 -*-

lib = File.expand_path("../lib/", __FILE__)
$LOAD_PATH.unshift lib unless $LOAD_PATH.include?(lib)
require 'graphene/version'

GEM_NAME    = 'graphene'

PKG_FILES =
  Dir.glob('{examples,lib,specs}/**/*.rb') +
  ['LICENSE', 'Rakefile', 'README.md', 'graphene.gemspec']

TEST_FILES = Dir.glob('specs/**/*.rb')

Gem::Specification.new do |s|
    s.name    = GEM_NAME
    s.version = Graphene::VERSION
    s.files   = PKG_FILES
    s.test_files = TEST_FILES
    s.executables   = []
    s.require_paths = ['lib']

    s.required_ruby_version = '>= 2.1.5'
    s.required_rubygems_version = Gem::Requirement.new(">= 1.3.3")
    s.add_development_dependency('rspec', '>= 2.0.0')
    s.add_dependency('eventmachine')

    s.author = "Alex Chien (aka Boombastic)"
    s.email = "alexchien97@gmail.com"
    s.date = %q{2015-11-01}
    s.description = %q{Graphene Ruby Rpc/Websocket library}
    s.summary = %q{Graphene Ruby Rpc/Websocket library}
    s.homepage = %q{http://github.com/AlexChien/graphene-ruby}
    s.licenses = ["Apache 2.0"]
end
