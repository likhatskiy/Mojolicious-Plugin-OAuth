package Mojolicious::Plugin::OAuth;

use strict;
use warnings;

use base 'Mojolicious::Plugin';

our $VERSION = '0.1';

use Mojo::Client;
use Net::OAuth::All;
use Data::Dumper;

use constant DEBUG => $ENV{'OAUTH_DEBUG'} || 0;

__PACKAGE__->attr('client' => sub {
	my $c = Mojo::Client
		->singleton
		->max_redirects(3);
	$c->ioloop->connect_timeout(15);
	$c;
});

__PACKAGE__->attr('conf', sub { +{} });

sub register {
	my ($self, $app, $conf)  = @_;
	
	$app->log->error("Config should be a HASH ref!") and return unless ref $conf eq 'HASH';
	$app->log->error("Config is empty!") and return unless %$conf;
	
	$self->conf($conf);
	
	$app->renderer
		->add_helper('oauth_login',   sub {
			my $c = $_[0];
			my $res = eval { $self->oauth_login(@_) };
			return $@ ? $self->_error($c, $@) : $res;
		})
		->add_helper('oauth_callback',   sub {
			my $c = $_[0];
			my $res = eval { $self->oauth_callback(@_) };
			return $@ ? $self->_error($c, $@) : $res;
		})
		->add_helper('oauth_request',   sub {
			my $c = $_[0];
			my $res = eval { $self->protected_request(@_) };
			return $@ ? $self->_error($c, $@) : $res;
		});
}

sub oauth_login {
	my ($self, $c, $oauth_provider) = @_;
	
	$c->stash('oauth_provider' => $oauth_provider);
	
	DEBUG && $self->_debug($c, "start oauth session");
	
	my $conf = $self->conf->{$oauth_provider} || {};
	return $self->_error($c, "Can`t get config!") unless %$conf;
	
	$c->session('oauth', {'oauth_provider' => $oauth_provider});
	
	my $oauth = Net::OAuth::All->new(%$conf);
	
	if ($oauth->{'module_version'} eq '2_0') {
		return $c->redirect_to($oauth->request('authorization')->to_url);
	} elsif (my $res = $self->make_request($c, $oauth->request('request_token'))) {
		$oauth->response->from_post_body($res->body);
		if (defined $oauth->token) {
			DEBUG && $self->_debug($c, "request_token ".$oauth->token);
			DEBUG && $self->_debug($c, "request_token_secret ".$oauth->token_secret);
			
			$c->session('oauth' => {
				(%{ $c->session('oauth') }),
				'request_token'        => $oauth->token,
				'request_token_secret' => $oauth->token_secret,
			});
			
			return $c->redirect_to($oauth->request('authorization')->to_url);
		}
	}
	return $self->_error($c, "Can`t get request token!!!");
}

sub oauth_callback {
	my ($self, $c) = @_;
	
	my $oauth_session = $c->session('oauth') || {};
	return $self->_error($c, "OAuth session is empty") unless %$oauth_session;
	
	$c->stash('oauth_provider' => $oauth_session->{'oauth_provider'});
	
	DEBUG && $self->_debug($c, "start oauth callback");
	
	my $conf = $self->conf->{$c->stash('oauth_provider')} || {};
	return $self->_error($c, "Can`t get config!") unless %$conf;
	
	my $oauth = Net::OAuth::All->new(
		%$conf,
		(
			'code'         => $c->param('code') || '',
			'token'        => $oauth_session->{'request_token'} || '',
			'token_secret' => $oauth_session->{'request_token_secret'} || '',
			'verifier'     => $c->param('oauth_verifier') || '',
		)
	);
	
	if (my $res = $self->make_request($c, $oauth->via('POST')->request('access_token'))) {
		$oauth->response->from_post_body($res->body);
		if ($oauth->token) {
			DEBUG && $self->_debug($c, "access_token ".$oauth->token);
			DEBUG && $self->_debug($c, "access_token_secret ".$oauth->token_secret);
			
			$c->session('oauth' => {
				%$oauth_session,
				'token_created'        => time,
				'access_token'         => $oauth->token,
				'refresh_token'        => $oauth->refresh_token,
				'access_token_expires' => $oauth->expires,
				'access_token_secret'  => $oauth->token_secret,
			});
			
			return 1;
		}
	}
	
	return $self->_error($c, "Can`t get access_token!!!");
}

sub protected_request {
	my $self   = shift;
	my $c      = shift;
	my $custom = $_[-3] && ref $_[-3] eq 'HASH' ? pop : {};
	my $extra  = $_[-2] && ref $_[-2] eq 'HASH' ? pop : {};
	my $params = pop || {};
	
	$c->stash('oauth_provider', +shift || '');
	
	my $conf = $self->conf->{$c->stash('oauth_provider')} || {};
	return $self->_error($c, "Can`t get config!") unless %$conf;
	
	my $oauth = Net::OAuth::All->new(%$conf);
	
	$oauth->via(+shift) if $_[0] && uc $_[0] !~ /^http/;
	$oauth->protected_resource_url(+shift) if $_[0];
	
	$params = {map {(my $t = $_) =~ s/^access_/oauth_/; $t => $params->{$_}} keys %$params} if $oauth->version ne '2_0';
	$oauth->from_hash(%$params);
	$oauth->clean_extra;
	$oauth->put_extra(%$extra);
	
	return $self->make_request($c, $oauth->request('protected_resource'), $custom);
}

sub make_request {
	my ($self, $c, $oauth, $custom) = @_;
	$custom ||= {};
	
	return unless $oauth;
	
	$custom->{'headers'}->{'Content-Type'} = 'application/x-www-form-urlencoded'
		if $oauth->via eq 'POST' && !$custom->{'headers'}->{'Content-Type'};
	
	$custom->{'headers'}->{'Authorization'} = $oauth->to_header
		if ($oauth->version eq '2_0' && $oauth->request_type eq 'protected_resource') || ($oauth->version ne '2_0' && $oauth->via eq 'POST');
	
	my $client = $self->client;
	my $tx     = $client->build_tx(
		$oauth->via
		=> ($oauth->via eq 'GET' || $custom->{'body'} ? $oauth->to_url($custom->{'body'} ? 1 : 0) : $oauth->url)
		=> ($custom->{'headers'} || {})
		=> $custom->{'body'} || $oauth->to_post_body
	);
	
	DEBUG && $self->_debug($c, $tx->req);
	
	$client->process($tx, sub { $tx = $_[1] });
	
	#~ warn Dumper $tx;
	DEBUG && $self->_debug($c, $tx->res);
	
	#~ return undef;
	return $tx->success || ($c->app->log->error('Error make_request ' . join(' : ', $tx->req, $tx->error, Dumper $oauth->to_hash)) and undef);
}

sub _debug {
	my ($self, $c, $error) = @_;
	$c->app->log->debug("'".$c->stash('oauth_provider')."' PROVIDER OAUTH DEBUG: $error");
}

sub _error {
	my ($self, $c, $error) = @_;
	
	delete $c->session->{'oauth'};
	$c->app->log->error("'".$c->stash('oauth_provider')."' PROVIDER OAUTH ERROR: $error");
	
	return;
}

1;
