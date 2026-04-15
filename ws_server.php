<?php

set_time_limit(0);
error_reporting(E_ALL);

date_default_timezone_set('Asia/Kolkata');

$host = "0.0.0.0";
$port = 8092;

$logFile = __DIR__ . "/ws_log_new.txt";
$dataFile = __DIR__ . "/offline_punch.json";
$apiUrl  = "https://digitalxplode.in/admin/api/biometric/punch";

// ---------------- LOG ----------------
function logMsg($msg) {
    global $logFile;
    file_put_contents($logFile, date("Y-m-d H:i:s") . " - " . $msg . PHP_EOL, FILE_APPEND);
}

// ---------------- TIME FIX ----------------
function fixTime($time, $utcOffset = null) {
    $time = str_replace("-T", " ", $time);
    $time = str_replace("Z", "", $time);

    if (!empty($utcOffset)) {
        $minutes = (int)$utcOffset;
        $time = date('Y-m-d H:i:s', strtotime($time . " +$minutes minutes"));
    }

    return $time;
}

// ---------------- SAVE FILE ----------------
function saveOffline($data) {
    global $dataFile;

    if (!file_exists($dataFile)) {
        file_put_contents($dataFile, json_encode([]));
    }

    $json = file_get_contents($dataFile);
    $existing = json_decode($json, true);

    if (!is_array($existing)) {
        $existing = [];
    }

    // duplicate रोकना
    foreach ($existing as $row) {
        if (isset($row['trans_id']) && $row['trans_id'] == $data['trans_id']) {
            return;
        }
    }

    $existing[] = $data;

    file_put_contents($dataFile, json_encode($existing));

    logMsg("Saved FILE: " . $data['trans_id']);
}

// ---------------- HANDSHAKE ----------------
function doHandshake($client, $headers) {
    if (preg_match("/Sec-WebSocket-Key: (.*)\r\n/", $headers, $match)) {
        $key = trim($match[1]);
        $acceptKey = base64_encode(pack('H*',
            sha1($key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
        ));

        $upgrade  = "HTTP/1.1 101 Switching Protocols\r\n";
        $upgrade .= "Upgrade: websocket\r\n";
        $upgrade .= "Connection: Upgrade\r\n";
        $upgrade .= "Sec-WebSocket-Accept: $acceptKey\r\n\r\n";

        socket_write($client, $upgrade);
    }
}

// ---------------- DECODE ----------------
function decode($data) {
    if (strlen($data) < 2) return "";

    $length = ord($data[1]) & 127;

    if ($length == 126) {
        $masks = substr($data, 4, 4);
        $payload = substr($data, 8);
    } elseif ($length == 127) {
        $masks = substr($data, 10, 4);
        $payload = substr($data, 14);
    } else {
        $masks = substr($data, 2, 4);
        $payload = substr($data, 6);
    }

    $text = '';
    for ($i = 0; $i < strlen($payload); $i++) {
        $text .= $payload[$i] ^ $masks[$i % 4];
    }

    return $text;
}

// ---------------- ENCODE ----------------
function encode($text) {
    $b1 = 0x81;
    $length = strlen($text);

    if ($length <= 125) {
        return pack('CC', $b1, $length) . $text;
    } elseif ($length <= 65535) {
        return pack('CCn', $b1, 126, $length) . $text;
    } else {
        return pack('CCNN', $b1, 127, 0, $length) . $text;
    }
}

// ---------------- SOCKET ----------------
$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_set_option($socket, SOL_SOCKET, SO_REUSEADDR, 1);

socket_bind($socket, $host, $port);
socket_listen($socket);

logMsg("Server started on $host:$port");

$clients = [];

while (true) {

    $read = $clients;
    $read[] = $socket;

    if (socket_select($read, $write, $except, 5) < 1) {
        continue;
    }

    // new connection
    if (in_array($socket, $read)) {
        $client = socket_accept($socket);

        if ($client !== false) {
            $clients[] = $client;
            socket_getpeername($client, $ip);
            logMsg("Connected: $ip");
        }

        unset($read[array_search($socket, $read)]);
    }

    foreach ($read as $client) {

        $data = @socket_read($client, 2048, PHP_BINARY_READ);

        if ($data === false || $data === "") {
            @socket_close($client);
            unset($clients[array_search($client, $clients)]);
            continue;
        }

        // handshake
        if (strpos($data, "GET") !== false) {
            doHandshake($client, $data);
            logMsg("Handshake OK");
            continue;
        }

        $decoded = decode($data);

        if (!str_contains($decoded, "<Message>")) continue;

        if (rand(1,10)==1) logMsg("RAW: " . $decoded);

        $xml = @simplexml_load_string($decoded);
        if (!$xml) continue;

        // REGISTER
        if (str_contains($decoded, "<Request>Register</Request>")) {
            $deviceSN = (string)$xml->DeviceSerialNo;
$token = uniqid();

$response = "<?xml version=\"1.0\"?>
<Message>
<Response>Register</Response>
<DeviceSerialNo>{$deviceSN}</DeviceSerialNo>
<Token>{$token}</Token>
<Result>OK</Result>
</Message>";
            socket_write($client, encode($response));
            continue;
        }

        // LOGIN
        if (str_contains($decoded, "<Request>Login</Request>")) {
            $deviceSN = (string)$xml->DeviceSerialNo;
$token = (string)$xml->Token;

$response = "<?xml version=\"1.0\"?>
<Message>
<Response>Login</Response>
<DeviceSerialNo>{$deviceSN}</DeviceSerialNo>
<Token>{$token}</Token>
<Result>OK</Result>
</Message>";

socket_write($client, encode($response));

logMsg("Login OK: " . $deviceSN);
continue;
        }

        // KEEPALIVE
        if (str_contains($decoded, "KeepAlive")) {
            $response = "<Message><Response>KeepAlive</Response><Result>OK</Result></Message>";
            socket_write($client, encode($response));
            continue;
        }

        // PUNCH
        if (isset($xml->Event) && (string)$xml->Event == "TimeLog_v2") {

            $userId = (string)$xml->UserID;
            $trans  = (string)$xml->TransID;

            // 🔥 FIXED TIME
            $time = fixTime((string)$xml->Time, (string)$xml->UtcTimezoneMinutes);

            $postDataArr = [
                'user_id'   => $userId,
                'io_time'   => date('YmdHis', strtotime($time)),
                'verify_mode' => 1,
                'io_mode'   => 0,
                'trans_id'  => $trans,
                'event'     => 'timelog',
                'raw_time'  => $time
            ];

            logMsg("PUNCH: " . json_encode($postDataArr));

            // ✅ ALWAYS SAVE FILE
            saveOffline($postDataArr);

            // ✅ API CALL
            $ch = curl_init($apiUrl);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($postDataArr));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 3);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);

            $res = curl_exec($ch);
            curl_close($ch);

            logMsg("API: " . $res);

            // ACK
            $response = "<Message><Response>TimeLog_v2</Response><TransID>{$trans}</TransID><Result>OK</Result></Message>";
            socket_write($client, encode($response));
        }
    }
}