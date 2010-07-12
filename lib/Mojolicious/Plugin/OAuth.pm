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
__PACKAGE__->attr('callback_url',      sub { '/oauth/'         });
__PACKAGE__->attr('oauth_session_url', sub { '/oauth_session/' });
__PACKAGE__->attr('after_callback',    sub { sub {$_[1]->redirect_to('/')} });

sub register {
	my ($self, $base, $args)  = @_;
	
	$base->log->error("Config is empty. Insert it with 'config' param!") and return unless $args->{'config'};
	DEBUG && $base->log->debug("OAUTH SESSION URL is ".$self->oauth_session_url.":oauth_provider/");
	
	$self->conf($args->{'config'});
	$self->error_path($args->{'error_path'});
	$self->after_callback($args->{'after_callback'}) if $args->{'after_callback'};
	
	$base->renderer->add_helper('oauth_url',       sub { $_[1] ? $self->oauth_session_url.$_[1].'/' : '/' });
	$base->renderer->add_helper('oauth_providers', sub { keys %{ $self->conf } });
	
	for ($base->routes) {
		$_->route($self->oauth_session_url.":oauth_provider", oauth_provider => qr/[\w\-]+/)
			->to(cb => sub {
				my $ctrl = shift;
				my $res = eval { $self->oauth_session($ctrl) };
				return $@ ? $self->_oauth_error($ctrl, $@) : $res;
			});
		
		$_->route($self->callback_url.":oauth_provider", oauth_provider => qr/[\w\-]+/)
			->to(cb => sub {
				my $ctrl = shift;
				my $res = eval { $self->oauth_callback($ctrl) };
				return $@ ? $self->_oauth_error($ctrl, $@) : $res;
			});
	}
}

sub oauth_session {
	my ($self, $ctrl) = @_;
	
	DEBUG && $self->_debug($ctrl, "start oauth session");
	
	my $conf = $self->conf->{ my $oauth_provider = $ctrl->param('oauth_provider') };
	return $self->_oauth_error($ctrl, "Can`t get config!") unless %$conf;
	
	if ($ctrl->req->headers->referrer) {
		my $ref = Mojo::URL->new($ctrl->req->headers->referrer || '');
		if ($ref->host eq $ctrl->req->url->base->host) {
			DEBUG && $self->_debug($ctrl, "save login referrer ".$ref->to_string);
			$ctrl->session('login_referrer' => $ref->to_string);
		} else {
			delete $ctrl->session->{'login_referrer'};
		}
	} else {
		delete $ctrl->session->{'login_referrer'};
	}
	
	my $www_oauth = Net::OAuth::All->new(%$conf);
	
	if ($www_oauth->{'module_version'} eq '2_0') {
		return $ctrl->redirect_to($www_oauth->request('authorization')->to_url);
	} elsif (my $res = $self->oauth_request($ctrl, $www_oauth->request('request_token'))) {
		$www_oauth->response->from_post_body($res->body);
		if (defined $www_oauth->token) {
			DEBUG && $self->_debug($ctrl, "request_token ".$www_oauth->token);
			DEBUG && $self->_debug($ctrl, "request_token_secret ".$www_oauth->token_secret);
			
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
	
	DEBUG && $self->_debug($ctrl, "start oauth callback");
	my $conf = $self->conf->{ my $oauth_provider = $ctrl->param('oauth_provider') };
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
	
	if (my $res = $self->oauth_request($ctrl, $www_oauth->request('access_token'))) {
		$www_oauth->response->from_post_body($res->body);
		if ($www_oauth->token) {
			DEBUG && $self->_debug($ctrl, "access_token ".$www_oauth->token);
			DEBUG && $self->_debug($ctrl, "access_token_secret ".$www_oauth->token_secret);
			
			$ctrl->session('oauth' => {
				%$oauth_session,
				'token_created'        => time,
				'access_token'         => $www_oauth->token,
				'refresh_token'        => $www_oauth->refresh_token,
				'access_token_expires' => $www_oauth->expires,
				'access_token_secret'  => $www_oauth->token_secret,
			});
			
			my $data = $self->oauth_request($ctrl, $www_oauth->request('protected_resource'));
			DEBUG && $self->_debug($ctrl, "oauth after callback");
			return $self->after_callback->($self, $ctrl, $data->json || {}) if $data;
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
	return $ctrl->redirect_to($self->error_path || '/');
}

sub _debug {
	my ($self, $ctrl, $error) = @_;
	$ctrl->app->log->debug("'".$ctrl->param('oauth_provider')."' PROVIDER DEBUG: $error");
}

1;
