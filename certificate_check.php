<?php

$jsonRequest    = file_get_contents('php://input');
$data           = json_decode($jsonRequest, true);

$timestamp = $data['request']['timestamp'];

if (time() - strtotime($timestamp) > 150) {
    header('HTTP/1.1 400 Bad Request');
    die();
}
if(function_exists('apache_request_headers')) {
    $headers = apache_request_headers();
}
else{
    $headers['Signature'] = $_SERVER['HTTP_SIGNATURE'];
    $headers['SignatureCertChainUrl'] = $_SERVER['HTTP_SIGNATURECERTCHAINURL'];
}

$signatuer = base64_decode($headers['Signature']);

$cert = openssl_x509_read(file_get_contents($headers['SignatureCertChainUrl']) );

$Certificate = openssl_x509_parse($cert,true);


if ($Certificate['subject']['CN'] != 'echo-api.amazon.com' || str_replace("DNS:", "", $Certificate['extensions']['subjectAltName']) != 'echo-api.amazon.com') {
    header('HTTP/1.1 400 Bad Request');
    die();
}

if ($Certificate['validTo_time_t'] < date("U")) {
    header('HTTP/1.1 400 Bad Request');
    die();  
}

$ssl_check = openssl_verify( $jsonRequest, base64_decode($headers['Signature']), file_get_contents($headers['SignatureCertChainUrl']), 'sha1' );

if ($ssl_check != '1') {
    header('HTTP/1.1 400 Bad Request');
    die();      
}
