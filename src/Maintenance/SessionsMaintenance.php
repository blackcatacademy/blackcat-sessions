<?php
declare(strict_types=1);

namespace BlackCat\Sessions\Maintenance;

use BlackCat\Core\Database;
use BlackCat\Database\Packages\SessionAudit\Definitions as SessionAuditDefinitions;
use BlackCat\Database\Packages\Sessions\Definitions as SessionsDefinitions;

final class SessionsMaintenance
{
    private function __construct() {}

    /**
     * Cleanup sessions + session_audit.
     *
     * @return array{sessions_deleted:int,session_audit_deleted:int,grace_hours:int,audit_days:int}
     */
    public static function cleanup(Database $db, int $graceHours = 24, int $auditDays = 90): array
    {
        $graceHours = max(0, $graceHours);
        $auditDays = max(0, $auditDays);

        $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $sessionCutoff = $now->modify('-' . $graceHours . ' hours')->format('Y-m-d H:i:s.u');
        $auditCutoff = $now->modify('-' . $auditDays . ' days')->format('Y-m-d H:i:s.u');

        $meta = ['component' => 'sessions_maintenance'];

        /** @var array{sessions_deleted:int,session_audit_deleted:int} $counts */
        $counts = $db->txWithMeta(
            function (Database $db) use ($sessionCutoff, $auditCutoff): array {
                $sessionsTbl = $db->quoteIdent(SessionsDefinitions::table());
                $auditTbl = $db->quoteIdent(SessionAuditDefinitions::table());

                $sessionsDeleted = (int)$db->execute(
                    "DELETE FROM {$sessionsTbl}
                      WHERE (revoked = TRUE AND last_seen_at < :cutoff)
                         OR (expires_at IS NOT NULL AND expires_at < :cutoff)",
                    [':cutoff' => $sessionCutoff]
                );

                $auditDeleted = (int)$db->execute(
                    "DELETE FROM {$auditTbl} WHERE created_at < :cutoff",
                    [':cutoff' => $auditCutoff]
                );

                return ['sessions_deleted' => $sessionsDeleted, 'session_audit_deleted' => $auditDeleted];
            },
            $meta,
            ['readOnly' => false]
        );

        return $counts + ['grace_hours' => $graceHours, 'audit_days' => $auditDays];
    }
}

