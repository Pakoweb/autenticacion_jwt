<?php
// api/api_welcome.php

header('Content-Type: application/json; charset=utf-8');

// Misma clave secreta
$secret_key = "clave";

// Mismo array de usuarios
$usuarios = [
    ["username" => "admin", "password" => "1234"],
    ["username" => "user",  "password" => "abcd"]
];

// Funciones auxiliares para JWT (Base64URL)
function base64url_decode($data) {
    $remainder = strlen($data) % 4;
    if ($remainder) {
        $padlen = 4 - $remainder;
        $data .= str_repeat('=', $padlen);
    }
    return base64_decode(strtr($data, '-_', '+/'));
}

// Valida el JWT: estructura, firma y expiración
function validarJWT($jwt, $secret_key) {
    $partes = explode('.', $jwt);
    if (count($partes) !== 3) {
        return null; // formato inválido
    }

    list($header_encoded, $payload_encoded, $firma_encoded) = $partes;

    // Recalcular firma
    $firma_check = hash_hmac(
        'sha256',
        $header_encoded . "." . $payload_encoded,
        $secret_key,
        true
    );

    $firma_check_encoded = rtrim(strtr(base64_encode($firma_check), '+/', '-_'), '=');

    // Comparar firma
    if (!hash_equals($firma_check_encoded, $firma_encoded)) {
        return null; // firma no válida
    }

    // Decodificar payload
    $payload_json = base64url_decode($payload_encoded);
    $payload = json_decode($payload_json, true);

    if (!$payload || !isset($payload["username"])) {
        return null;
    }

    // Comprobar expiración
    if (isset($payload["exp"]) && time() > $payload["exp"]) {
        return null; // token expirado
    }

    return $payload;
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405); // Method Not Allowed
    echo json_encode(["error" => "Método no permitido"]);
    exit;
}

// Obtener cabecera Authorization
$headers = function_exists('getallheaders') ? getallheaders() : [];
$authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';

if (!$authHeader || strpos($authHeader, 'Bearer ') !== 0) {
    // Falta token → 403 Forbidden
    http_response_code(403);
    echo json_encode([
        "error" => "No tienes permisos. Falta token."
    ]);
    exit;
}

$token = substr($authHeader, 7); // quitar "Bearer "

$payload = validarJWT($token, $secret_key);

if ($payload === null) {
    // Token inválido o caducado → 403
    http_response_code(403);
    echo json_encode([
        "error" => "Token inválido o caducado."
    ]);
    exit;
}

$username = $payload["username"];

// Comprobar que el usuario sigue existiendo en el array
$usuarioExiste = false;
foreach ($usuarios as $u) {
    if ($u["username"] === $username) {
        $usuarioExiste = true;
        break;
    }
}

if (!$usuarioExiste) {
    http_response_code(403);
    echo json_encode([
        "error" => "Usuario no válido."
    ]);
    exit;
}

// OK → devolvemos info del usuario
echo json_encode([
    "username"     => $username,
    "horaServidor" => date('H:i:s'),
    "message"      => "Bienvenido, $username"
]);
