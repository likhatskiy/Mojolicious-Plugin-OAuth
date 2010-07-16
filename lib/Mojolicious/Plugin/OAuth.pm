package Mojolicious::Plugin::OAuth;

use strict;
use warnings;

use base 'Mojolicious::Plugin';

our $VERSION = '0.04';

use Net::OAuth::All;
use Data::Dumper;

use constant DEBUG => $ENV{'OAUTH_DEBUG'} || 0;

__PACKAGE__->attr('conf',              sub { {} });
__PACKAGE__->attr('error_path',        sub { '' });
__PACKAGE__->attr('default_callback_url', sub { '/oauth/'         });
__PACKAGE__->attr('default_session_url',  sub { '/oauth_session/' });
__PACKAGE__->attr('after_callback',    sub { sub {$_[1]->redirect_to('/')} });

sub register {
	my ($self, $base, $args)  = @_;
	
	$base->log->error("Config is empty. Insert it with 'config' param!") and return unless $args->{'config'};
	
	$self->conf(my $conf = $args->{'config'});
	$self->error_path($args->{'error_path'});
	$self->after_callback($args->{'after_callback'}) if $args->{'after_callback'};
	
	$base->renderer->add_helper('oauth_url',       sub { $_[1] ? $self->session_url($_[1]) : '/' });
	$base->renderer->add_helper('oauth_providers', sub { keys %{ $self->conf } });
	
	for my $r ($base->routes) {
		my $default_sessions  = [];
		my $default_callbacks = [];
		
		foreach (keys %$conf) {
			if ($conf->{$_}->{'session_url'}) {
				$r->route( $conf->{$_}->{'session_url'} )
					->to(oauth_provider => $_, cb => sub {
						my $c = shift;
						my $res = eval { $self->oauth_session($c) };
						return $@ ? $self->_oauth_error($c, $@) : $res;
					});
				DEBUG && $base->log->debug("OAUTH DEBUG: created session route '$conf->{$_}->{'session_url'}' from config");
			} else {
				DEBUG && $base->log->debug("OAUTH DEBUG: created default session route '".$self->default_session_url."$_/'");
				
				push @$default_sessions, $_;
			}
			
			if ($conf->{$_}->{'callback'} || $conf->{$_}->{'redirect_uri'}) {
				$r->route( Mojo::URL->new($conf->{$_}->{'callback'} || $conf->{$_}->{'redirect_uri'})->path )
					->to(oauth_provider => $_, cb => sub {
						my $c = shift;
						my $res = eval { $self->oauth_callback($c) };
						return $@ ? $self->_oauth_error($c, $@) : $res;
					});
				DEBUG && $base->log->debug("OAUTH DEBUG: created callback route '".($conf->{$_}->{'callback'} || $conf->{$_}->{'redirect_uri'})."' from config");
			} else {
				DEBUG && $base->log->debug("OAUTH DEBUG: created default callback route '".$self->default_callback_url."$_/'");
				
				push @$default_callbacks, $_;
			}
		}
		
		if (@$default_sessions) {
			my $t = join '|', @$default_sessions;
			$r->route($self->default_session_url.":oauth_provider", oauth_provider => qr/$t/)
				->to(cb => sub {
					my $c = shift;
					my $res = eval { $self->oauth_session($c) };
					return $@ ? $self->_oauth_error($c, $@) : $res;
				});
		}
		
		
		if (@$default_callbacks) {
			my $t = join '|', @$default_callbacks;
			$r->route($self->default_callback_url.":oauth_provider", oauth_provider => qr/$t/)
				->to(cb => sub {
					my $c = shift;
					my $res = eval { $self->oauth_callback($c) };
					return $@ ? $self->_oauth_error($c, $@) : $res;
				});
		}
	}
}

sub oauth_session {
	my ($self, $c) = @_;
	
	DEBUG && $self->_debug($c, "start oauth session");
	
	my $conf = $self->conf->{ my $oauth_provider = $c->param('oauth_provider') };
	return $self->_oauth_error($c, "Can`t get config!") unless %$conf;
	
	if ($c->req->headers->referrer) {
		my $ref = Mojo::URL->new($c->req->headers->referrer || '');
		if ($ref->host eq $c->req->url->base->host) {
			DEBUG && $self->_debug($c, "save login referrer ".$ref->to_string);
			$c->session('login_referrer' => $ref->to_string);
		} else {
			delete $c->session->{'login_referrer'};
		}
	} else {
		delete $c->session->{'login_referrer'};
	}
	
	my $www_oauth = Net::OAuth::All->new(%$conf);
	
	if ($www_oauth->{'module_version'} eq '2_0') {
		return $c->redirect_to($www_oauth->request('authorization')->to_url);
	} elsif (my $res = $self->oauth_request($c, $www_oauth->request('request_token'))) {
		$www_oauth->response->from_post_body($res->body);
		if (defined $www_oauth->token) {
			DEBUG && $self->_debug($c, "request_token ".$www_oauth->token);
			DEBUG && $self->_debug($c, "request_token_secret ".$www_oauth->token_secret);
			
			$c->session('oauth' => {
				%{ $c->session('oauth') || {} },
				'request_token'        => $www_oauth->token,
				'request_token_secret' => $www_oauth->token_secret,
			});
			
			return $c->redirect_to($www_oauth->request('authorization')->to_url);
		}
	}
	return $self->_oauth_error($c, "Can`t get request token!!!");
}

sub oauth_callback {
	my ($self, $c) = @_;
	
	DEBUG && $self->_debug($c, "start oauth callback");
	my $conf = $self->conf->{ my $oauth_provider = $c->param('oauth_provider') };
	return $self->_oauth_error($c, "Can`t get config!") unless %$conf;
	
	my $oauth_session = $c->session('oauth') || {};
	my $www_oauth = Net::OAuth::All->new(
		%$conf,
		(
			'code'         => $c->param('code') || '',
			'token'        => $oauth_session->{'request_token'} || '',
			'token_secret' => $oauth_session->{'request_token_secret'} || '',
			'verifier'     => $c->param('oauth_verifier') || '',
		)
	);
	
	if (my $res = $self->oauth_request($c, $www_oauth->request('access_token'))) {
		$www_oauth->response->from_post_body($res->body);
		if ($www_oauth->token) {
			DEBUG && $self->_debug($c, "access_token ".$www_oauth->token);
			DEBUG && $self->_debug($c, "access_token_secret ".$www_oauth->token_secret);
			
			$c->session('oauth' => {
				%$oauth_session,
				'token_created'        => time,
				'access_token'         => $www_oauth->token,
				'refresh_token'        => $www_oauth->refresh_token,
				'access_token_expires' => $www_oauth->expires,
				'access_token_secret'  => $www_oauth->token_secret,
			});
			
			my $data = $self->oauth_request($c, $www_oauth->request('protected_resource'));
			DEBUG && $self->_debug($c, "oauth after callback");
			return $self->after_callback->($self, $c, $data->json || {}) if $data;
			return $self->_oauth_error($c, "Can`t get protected_resource!!!");
		}
	}
	
	return $self->_oauth_error($c, "Can`t get access_token!!!");
}

sub oauth_request {
	my ($self, $c, $request) = @_;
	return unless $request;
	
	my $response = undef;
	my $client   = $c->client;
	if ($request->{'request_method'} eq 'GET') {
		$response = $client->get($request->to_url);
	} else {
		#~ $response = $client->post($request->to_url);
	}
	
	return $response->success || ($c->app->log->error('Error oauth_request ' . join(' : ', $request->to_url, $response->error, Dumper $request)) and undef);
}

sub _oauth_error {
	my ($self, $c, $error) = @_;
	$c->session('oauth' => {});
	
	$c->app->log->error("'".$c->param('oauth_provider')."' PROVIDER ERROR: $error");
	return $c->redirect_to($self->error_path || '/');
}

sub session_url {
	my ($self, $provider) = @_;
	warn $provider;
	$self->conf->{$provider}->{'session_url'} || $self->default_session_url.$provider.'/';
}

sub _debug {
	my ($self, $c, $error) = @_;
	$c->app->log->debug("'".$c->param('oauth_provider')."' PROVIDER OAUTH DEBUG: $error");
}

1;
