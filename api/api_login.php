<?php
// api/api_login.php

header('Content-Type: application/json; charset=utf-8');

// Clave secreta para firmar el JWT
$secret_key = "clave";

// Array de usuarios (simula base de datos)
$usuarios = [
    ["username" => "admin", "password" => "1234"],
    ["username" => "user",  "password" => "abcd"]
];

// Funciones auxiliares para JWT (Base64URL)
function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

// Generar JWT HS256 manualmente
function generarJWT($username, $secret_key) {
    // HEADER
    $header = [
        "alg" => "HS256",
        "typ" => "JWT"
    ];

    // PAYLOAD (incluimos username, iat, exp, iss)
    $tiempoActual = time();
    $payload = [
        "username" => $username,
        "iat"      => $tiempoActual,
        "exp"      => $tiempoActual + 3600, // expira en 1 hora
        "iss"      => "mi-aplicacion-escuela"
    ];

    $header_encoded  = base64url_encode(json_encode($header));
    $payload_encoded = base64url_encode(json_encode($payload));

    // FIRMA HS256
    $signature = hash_hmac('sha256', $header_encoded . "." . $payload_encoded, $secret_key, true);
    $signature_encoded = base64url_encode($signature);

    // JWT completo
    return $header_encoded . "." . $payload_encoded . "." . $signature_encoded;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405); // Method Not Allowed
    echo json_encode(["error" => "Método no permitido"]);
    exit;
}

// Leer JSON enviado por fetch
$input = file_get_contents('php://input');
$data = json_decode($input, true);

$username = $data["username"] ?? "";
$password = $data["password"] ?? "";

$credencialesCorrectas = false;

foreach ($usuarios as $u) {
    if ($u["username"] === $username && $u["password"] === $password) {
        $credencialesCorrectas = true;
        break;
    }
}

if ($credencialesCorrectas) {
    $token = generarJWT($username, $secret_key);

    echo json_encode([
        "token"    => $token,
        "username" => $username,
        "message"  => "Login correcto"
    ]);
} else {
    // Credenciales incorrectas → 401 (el cliente redirigirá a no_permisos.html)
    http_response_code(401);
    echo json_encode([
        "error" => "Credenciales inválidas"
    ]);
}
