<?php


// api_login.php (POST /api/login)
header('Content-Type: application/json');

// Array predefinido de usuarios (Requisito: Simulación de BBDD)
$usuarios = [
    ["username" => "admin", "password" => "1234"],
    ["username" => "user", "password" => "abcd"]
];

// SECRETO DEL SERVIDOR (DEBE SER EL MISMO EN AMBOS ARCHIVOS PHP)
$secret = "MI_SECRETO_SUPER_SEGURO_PARA_JWT";

// ----------------------------------------------------
// 1. Validar credenciales
// ----------------------------------------------------
$input = json_decode(file_get_contents("php://input"), true);
$username = $input["username"] ?? null;
$password = $input["password"] ?? null;

$usuario_valido = false;
foreach ($usuarios as $u) {
    if ($u["username"] === $username && $u["password"] === $password) {
        $usuario_valido = true;
        break;
    }
}

if (!$usuario_valido) {
    // Respuesta 401 Unauthorized (Requisito 2)
    http_response_code(401);
    echo json_encode(["error" => "Credenciales incorrectas"]);
    exit;
}

// ----------------------------------------------------
// 2. Generar JWT
// ----------------------------------------------------

// HEADER JWT (Base64 URL Safe)
$header = json_encode(['alg' => 'HS256', 'typ' => 'JWT']);
// Función para codificar en Base64 URL Safe
$headerB64 = rtrim(strtr(base64_encode($header), '+/', '-_'), '=');

// PAYLOAD JWT (Base64 URL Safe): Incluye datos del usuario, tiempo de emisión (iat) y expiración (exp)
$payload = json_encode([
    "username" => $username,
    "role" => "user",
    "iat" => time(),
    "exp" => time() + 3600 // Expira en 1 hora (3600 segundos)
]);
$payloadB64 = rtrim(strtr(base64_encode($payload), '+/', '-_'), '=');

// FIRMA (Signature)
$signature = hash_hmac('sha256', "$headerB64.$payloadB64", $secret, true);
$signatureB64 = rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');

// TOKEN FINAL
$jwt = "$headerB64.$payloadB64.$signatureB64";

echo json_encode([
    "status" => "ok",
    "token" => $jwt
]);
?>