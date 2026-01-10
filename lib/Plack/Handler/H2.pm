package Plack::Handler::H2;

use strict;
use warnings;
use File::Temp;
use Plack::Handler::H2::Writer;

require XSLoader;
our $VERSION = '0.0.1';
XSLoader::load(__PACKAGE__, $VERSION);

sub new {
    my ($class, %args) = @_;
    return bless \%args, $class;
}

sub run {
    my ($self, $app) = @_;

    die "Unsupported OS for Plack::Handler::H2" if $^O !~ /linux|darwin|freebsd|openbsd/i;

    if (!defined $self->{ssl_cert_file} || !defined $self->{ssl_key_file}) {
        my $cert_dir = File::Temp->newdir( CLEANUP => 1 );
        warn("SSL certificate or key file not provided. Generating self-signed certificate.\n");
        ($self->{ssl_cert_file}, $self->{ssl_key_file}) = $self->_generate_self_signed_cert($cert_dir);
        warn("Generated self-signed certificate at $self->{ssl_cert_file} and key at $self->{ssl_key_file}\n");
        warn("!!! WARNING !!! Self-signed certificates may not be trusted by clients.\n");
    }

    if (!$self->{port} && $self->{port} ne '0') {
        $self->{port} = 5000;
    }

    my $res = ph2_run_wrapper($self, $app, {
        ssl_cert => $self->{ssl_cert_file},
        ssl_key  => $self->{ssl_key_file},
        address  => $self->{host} // '0.0.0.0',
        port     => $self->{port},
        timeout  => $self->{timeout} // 120,
        read_timeout => $self->{read_timeout} // 60,
        write_timeout => $self->{write_timeout} // 60,
        request_timeout => $self->{request_timeout} // 30,
        max_request_body_size => $self->{max_request_body_size} // 10 * 1024 * 1024 # (10 MB)
    });
    return $res;
}

sub _generate_self_signed_cert {
    my ($self, $cert_dir) = @_;

    my $cert_file = File::Temp->new( DIR => $cert_dir, SUFFIX => '.crt' );
    my $key_file = File::Temp->new( DIR => $cert_dir, SUFFIX => '.key' );

    my $openssl_check = `which openssl`;
    chomp($openssl_check);
    unless ($openssl_check) {
        die "OpenSSL is not installed or not found in PATH. Cannot generate self-signed certificate.";
    }

    my $cmd = "openssl req -x509 -newkey rsa:2048 -keyout $key_file -out $cert_file -days 365 -nodes -subj '/CN=localhost' 2>/dev/null";
    system($cmd);

    return ($cert_file, $key_file);
}

sub _responder {
    my ($env, $session) = @_;
    my $responder = sub {
        my $response = shift;
        if (ref($response) ne 'ARRAY' || (@$response < 2 || @$response > 3)) {
            warn "Invalid PSGI response in responder";
            return [500, ['Content-Type' => 'text/plain'], ['Internal Server Error: invalid response from application']];
        }

        if (scalar @$response == 2) {
            ph2_stream_write_headers_wrapper($env, $session, $response);
            return Plack::Handler::H2::Writer->new({
                response => $response,
                writer => sub {
                    my ($end_stream, $data) = @_;
                    ph2_stream_write_data_wrapper($env, $session, $end_stream, $data);    
                }
            });
        }

        return $response;
    };

    return $responder;
}

1;
