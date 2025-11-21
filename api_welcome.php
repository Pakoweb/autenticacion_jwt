<?php
// api_welcome.php (GET /api/welcome)
header('Content-Type: application/json');

// SECRETO DEL SERVIDOR (DEBE SER EL MISMO QUE EN api_login.php)
$secret = "MI_SECRETO_SUPER_SEGURO_PARA_JWT";

// ----------------------------------------------------
// 1. Extraer y verificar la cabecera Authorization
// ----------------------------------------------------
$headers = getallheaders();
$auth = $headers["Authorization"] ?? null;

if (!isset($auth) || substr($auth, 0, 7) !== "Bearer ") {
    // 403 Forbidden (Falta el token) (Requisito 4)
    http_response_code(403);
    echo json_encode(["error" => "Acceso prohibido. Falta token Bearer"]);
    exit;
}

$jwt = str_replace("Bearer ", "", $auth);

// Separar el token en sus 3 partes
$partes = explode(".", $jwt);

if (count($partes) !== 3) {
    // 403 Forbidden (Token malformado) (Requisito 4)
    http_response_code(403);
    echo json_encode(["error" => "Token malformado"]);
    exit;
}

list($headerB64, $payloadB64, $signatureB64) = $partes;

// ----------------------------------------------------
// 2. Validar expiración y decodificar Payload
// ----------------------------------------------------

// Decodificar payload (Base64 URL Safe a JSON)
$payloadJson = base64_decode(strtr($payloadB64, '-_', '+/'), true);
if ($payloadJson === false) {
    http_response_code(403);
    echo json_encode(["error" => "Payload no decodificable"]);
    exit;
}
$payload = json_decode($payloadJson, true);

// Expiración (exp)
if (!isset($payload["exp"]) || $payload["exp"] < time()) {
    // 403 Forbidden (Token caducado) (Requisito 4)
    http_response_code(403);
    echo json_encode(["error" => "Token caducado"]);
    exit;
}

// ----------------------------------------------------
// 3. Validar Firma (INTEGRIDAD)
// ----------------------------------------------------

// Generar la firma que SÍ ESPERAMOS usando el secreto
$firmaGenerada = hash_hmac('sha256', "$headerB64.$payloadB64", $secret, true);
$firmaGeneradaB64 = rtrim(strtr(base64_encode($firmaGenerada), '+/', '-_'), '=');

// Comparar la firma que vino con el token con la firma que generamos
// hash_equals se usa para evitar ataques de tiempo (timing attacks)
if (!hash_equals($firmaGeneradaB64, $signatureB64)) {
    // 403 Forbidden (Firma inválida - el token fue alterado o no se usó el secreto correcto)
    http_response_code(403);
    echo json_encode(["error" => "Firma inválida"]);
    exit;
}

// Todo correcto. El JWT es válido, no ha expirado y no ha sido alterado.
echo json_encode([
    "ok" => true,
    "mensaje" => "Token JWT válido",
    "datos_usuario" => [
        "username" => $payload['username'],
        "role" => $payload['role']
    ]
]);
?>
