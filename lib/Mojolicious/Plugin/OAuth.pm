package Mojolicious::Plugin::OAuth;

use strict;
use warnings;

use base 'Mojolicious::Plugin';
use Net::OAuth::All;
use Data::Dumper;

our $DEBUG = 0;

sub register {
	my ($self, $base, $args)  = @_;
	$DEBUG                    = $args->{'debug'};
	$self->{'__CONFIG'      } = $args->{'config'} || ($base->log->error("Config is empty. Insert it with 'config' param!") and return);
	$self->{'error_path'    } = $args->{'error_path'};
	$self->{'after_callback'} = $args->{'after_callback'} || sub {$_[1]->redirect_to('/')};
	
	for ($base->routes) {
		$_->route("/oauth_session/:oauth_provider", oauth_provider => qr/[0-9A-Z_\-]+/i)
			->to(callback => sub {
				my $ctrl = shift;
				my $res = eval { $self->oauth_session($ctrl) };
				return $@ ? $self->_oauth_error($ctrl, $@) : $res;
			});
		
		$_->route("/oauth/:oauth_provider", oauth_provider => qr/[0-9A-Z_\-]+/i)
			->to(callback => sub {
				my $ctrl = shift;
				my $res = eval { $self->oauth_callback($ctrl) };
				return $@ ? $self->_oauth_error($ctrl, $@) : $res;
			});
	}
}

sub debug {$DEBUG ? 1 : 0}

sub config {
	(shift->{'__CONFIG'} || {})->{+shift} || {};
}

sub after_callback {
	my $self = shift;
	$self->{'after_callback'}->($self, @_);
}

sub oauth_session {
	my ($self, $ctrl) = @_;
	
	my $conf = $self->config( my $oauth_provider = $ctrl->param('oauth_provider') );
	$self->_debug($ctrl, "start oauth session") if $self->debug;
	return $self->_oauth_error($ctrl, "Can`t get config!") unless %$conf;
	
	my $www_oauth = Net::OAuth::All->new(%$conf);
	
	if ($www_oauth->{'module_version'} eq '2_0') {
		return $ctrl->redirect_to($www_oauth->request('authorization')->to_url);
	} elsif (my $res = $self->oauth_request($ctrl, $www_oauth->request('request_token'))) {
		$www_oauth->response->from_post_body($res->body);
		if (defined $www_oauth->token) {
			$self->_debug($ctrl, "request_token ".$www_oauth->token) if $self->debug;
			$self->_debug($ctrl, "request_token_secret ".$www_oauth->token_secret) if $self->debug;
			
			$ctrl->session('oauth' => {
				%{ $ctrl->session('oauth') || {} },
				'request_token'        => $www_oauth->token,
				'request_token_secret' => $www_oauth->token_secret,
			});
			
			return $ctrl->redirect_to($www_oauth->request('authorization')->to_url);
		}
	}
	return $self->_oauth_error($ctrl, "Can`t get request token!!!");
}

sub oauth_callback {
	my ($self, $ctrl) = @_;
	
	my $conf = $self->config( my $oauth_provider = $ctrl->param('oauth_provider') );
	$self->_debug($ctrl, "start oauth callback") if $self->debug;
	return $self->_oauth_error($ctrl, "Can`t get config!") unless %$conf;
	
	my $oauth_session = $ctrl->session('oauth') || {};
	my $www_oauth = Net::OAuth::All->new(
		%$conf,
		(
			'code'         => $ctrl->param('code') || '',
			'token'        => $oauth_session->{'request_token'} || '',
			'token_secret' => $oauth_session->{'request_token_secret'} || '',
			'verifier'     => $ctrl->param('oauth_verifier') || '',
		)
	);
	
	warn Dumper $www_oauth;
	#~ $ctrl->cookie($_ => '', {'path' => '/'}) for qw/request_token request_token_secret access_token refresh_token access_token_expires access_token_secret/;
	
	if (my $res = $self->oauth_request($ctrl, $www_oauth->request('access_token'))) {
		$www_oauth->response->from_post_body($res->body);
		if ($www_oauth->token) {
			$self->_debug($ctrl, "access_token ".$www_oauth->token) if $self->debug;
			$self->_debug($ctrl, "access_token_secret ".$www_oauth->token_secret) if $self->debug;
			
			$ctrl->session('oauth' => {
				%$oauth_session,
				'token_created'        => time,
				'access_token'         => $www_oauth->token,
				'refresh_token'        => $www_oauth->refresh_token,
				'access_token_expires' => $www_oauth->expires,
				'access_token_secret'  => $www_oauth->token_secret,
			});
			
			my $data = $self->oauth_request($ctrl, $www_oauth->request('protected_resource'));
			$self->_debug($ctrl, "oauth after callback") if $self->debug;
			return $self->after_callback($ctrl, $data->json || {}) if $data;
			return $self->_oauth_error($ctrl, "Can`t get protected_resource!!!");
		}
	}
	
	return $self->_oauth_error($ctrl, "Can`t get access_token!!!");
}

sub oauth_request {
	my ($self, $ctrl, $request) = @_;
	return unless $request;
	
	my $response = undef;
	my $client   = $ctrl->client;
	if ($request->{'request_method'} eq 'GET') {
		$response = $client->get($request->to_url);
	} else {
		#~ $response = $client->post($request->to_url);
	}
	
	return $response->success || ($ctrl->app->log->error('Error oauth_request ' . join(' : ', $request->to_url, $response->error, Dumper $request)) and undef);
}

sub _oauth_error {
	my ($self, $ctrl, $error) = @_;
	$ctrl->session('oauth' => {});
	
	$ctrl->app->log->error("'".$ctrl->param('oauth_provider')."' PROVIDER ERROR: $error");
	return $ctrl->redirect_to($self->{'error_path'} || '/');
}

sub _debug {
	my ($self, $ctrl, $error) = @_;
	$ctrl->app->log->debug("'".$ctrl->param('oauth_provider')."' PROVIDER DEBUG: $error");
}

1;
