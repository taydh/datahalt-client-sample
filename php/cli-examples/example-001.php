<?php
// Description:
// Make authentication and perform simple queries with DataHalt server
// 
// Please change and check config variable below accordingly
// 
// run from command line > php example-001.php

require('../vendor/autoload.php');

$baseUrl = 'http://localhost:8000'; // datahalt server base url
$config = [
	'authURL' => $baseUrl . '/auth.php', // datahalt authentication endpoint
	'queryURL' => $baseUrl . '/query.php', // datahalt query endpoint
	'clientId' => 'client001_5e065a976391b46f', // see datahalt (server) client settings
	'otpKey' => 'bb60142201dfa04d47901bfbfcd2c2e0', // see datahalt (server) client settings
];

////////////// 1. Authenticate ////////////////////////

// generate OTP
$g = new \Sonata\GoogleAuthenticator\GoogleAuthenticator();
$otp = $g->getCode($config['otpKey']);
// echo "OTP: {$otp}" . PHP_EOL . PHP_EOL;

// send request using clientId and otp
$data = http_build_query(['clientId' => $config['clientId'], 'otp' => $otp]);
$context = stream_context_create([
	'http' => [
		'ignore_errors' => true,
		'method' => 'POST',
		'header' => 'Content-Type: application/x-www-form-urlencoded' . PHP_EOL
					.'Content-Length: '. strlen($data) . PHP_EOL,
		'content' => $data,
	]]);
$responseContent = file_get_contents($config['authURL'], false, $context);
// echo 'Response content: ' . $responseContent . PHP_EOL . PHP_EOL;

// if everything is working correcly, 
// server will return properties to help us create the query requests
$responseContent = @json_decode($responseContent);
if (!$responseContent || $responseContent->status != 'ok') {
	echo 'Response content: ' . $responseContent . PHP_EOL . PHP_EOL;
	die('Invalid JSON response');
}

// $authData values should be stored approximately until period defined in $authData->expiresAt
$authData = $responseContent->data;

////////////// 2. QUERYING ////////////////////////

function base64url_encode($string) {
	return rtrim(strtr(base64_encode($string), '+/', '-_'), '=');
}

function createRequestJWT($lifeTime, $authInfoToken, $checksum) {
	$now = time();
	$head = base64url_encode(json_encode([
		"alg" => "HS256",
		"typ" => "JWT"
	]));
	$payload = base64url_encode(json_encode([
		"iss" => $now,
		"exp" => $now + $lifeTime,
		"authInfoToken" => $authInfoToken,
	]));
	$combo = "$head.$payload";
	$signature = base64url_encode(hash_hmac("sha256", $combo, $checksum, true));
	
	return "$combo.$signature";
}

function sendQuery($queryUrl, $authInfoToken, $queryData) {
	$queryData = json_encode($queryData);
	
	// create request authorization bearer jwt with smalles possible lifetime for each request (ie, 7s)
	$jwt = createRequestJWT(7, $authInfoToken, md5($queryData));
	// echo 'Request Authorization JWT: ' . $jwt . PHP_EOL . PHP_EOL;
	
	$context = stream_context_create([
		'http' => [
			'ignore_errors' => true,
			'method' => 'POST',
			'header' => 'Content-Type: application/json' . PHP_EOL
						.'Content-Length: '. strlen($queryData) . PHP_EOL
						.'Authorization: Bearer ' . $jwt,
			'content' => $queryData,
		]]);
	$responseContent = file_get_contents($queryUrl, false, $context);

	// if everything is working correcly, 
	// server will provide us with JSON object(s) of query result
	$responseContent = @json_decode($responseContent);
	if (!$responseContent || $responseContent->status != 'ok') {
		echo 'Response content: ' . $responseContent . PHP_EOL . PHP_EOL;
		die('Invalid JSON response');
	}

	return $responseContent->data;
}

//// 1st sample query
$queryData = [
	'map' => ['to' => 'keyval'], 
	'query' => ['text' => 'select * from keyval']];
echo 'TeleQuery data: ' . print_r($queryData, true) . PHP_EOL;

$queryResult = sendQuery($config['queryURL'], $authData->authInfoToken, $queryData);
echo 'TeleQuery Result: ' . print_r($queryResult, true) .PHP_EOL.PHP_EOL;

//// 2nd sample query
$queryData = [
	'map' => ['to' => 'total'], 
	'query' => ['text' => "select count(*) as total from keyval"]];
echo 'TeleQuery data: ' . print_r($queryData, true) . PHP_EOL;

$queryResult = sendQuery($config['queryURL'], $authData->authInfoToken, $queryData);
echo 'TeleQuery Result: ' . print_r($queryResult, true) .PHP_EOL.PHP_EOL;

// now, you should be able to make any sql queries permitted to the configured user account.
//
// TeleQuery query data format is designed to fetch and execute multiple queries 
// in single request and within it using single database connection handler.
// Thus, it able to other things that will covered in other documentation, including:
// - execute insert, update, and delete statement
// - stepped queries for given results, either once or for each result
