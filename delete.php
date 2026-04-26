<?php
session_start();
require 'db.php';
require 'csrf.php';

// Проверяем CSRF-токен перед удалением
// В реальном приложении удаление должно быть через POST,
// но в учебном проекте оставлен GET с токеном в URL
if (!CsrfGuard::validate($_GET['csrf_token'] ?? '')) {
    http_response_code(403); // 403 Forbidden — возможная CSRF-атака
    die('Ошибка безопасности: неверный CSRF-токен.');
}

$id = (int)($_GET['id'] ?? 0);

if ($id > 0) {
    $stmt = $pdo->prepare('DELETE FROM notes WHERE id = ? AND user_id = ?');
    $stmt->execute([$id, $currentUserId]);
}

header('Location: index.php');
exit;