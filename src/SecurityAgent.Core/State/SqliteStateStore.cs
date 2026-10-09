using Microsoft.Data.Sqlite;
using SecurityAgent.Core.Alerts;
using SecurityAgent.Core.Events;

namespace SecurityAgent.Core.State;

public sealed class SqliteStateStore : IStateStore, IDisposable
{
    private readonly StateStoreOptions _opt;
    private readonly TimeProvider _time;
    private readonly SqliteConnection _db;
    private readonly object _gate = new();

    public SqliteStateStore(StateStoreOptions options, TimeProvider? time = null)
    {
        _opt = options;
        _time = time ?? TimeProvider.System;
        var dir = Path.GetDirectoryName(options.DatabasePath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        _db = new SqliteConnection($"Data Source={options.DatabasePath};Pooling=False");
        _db.Open();
        // auto_vacuum debe fijarse antes de crear tablas: permite devolver espacio tras purgar.
        Exec("PRAGMA auto_vacuum = INCREMENTAL;");
        Exec("PRAGMA journal_mode = WAL;");
        Exec("""
            CREATE TABLE IF NOT EXISTS events(
              id TEXT PRIMARY KEY, ts INTEGER NOT NULL, source TEXT NOT NULL, type TEXT NOT NULL,
              severity INTEGER NOT NULL, actor TEXT, ip TEXT, target TEXT, detail TEXT);
            CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
            CREATE INDEX IF NOT EXISTS ix_events_ip ON events(ip);
            CREATE TABLE IF NOT EXISTS blocks(
              ip TEXT PRIMARY KEY, rule_id TEXT NOT NULL, reason TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS alerts(
              id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, ts INTEGER NOT NULL, severity INTEGER NOT NULL,
              group_key TEXT, message TEXT NOT NULL, event_ids TEXT NOT NULL, mode TEXT NOT NULL, action TEXT);
            CREATE INDEX IF NOT EXISTS ix_alerts_ts ON alerts(ts);
            CREATE TABLE IF NOT EXISTS cursors(name TEXT PRIMARY KEY, value INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS audits(kind TEXT PRIMARY KEY, status TEXT NOT NULL, ts INTEGER NOT NULL, summary TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS rule_state(rule_id TEXT PRIMARY KEY, mode TEXT NOT NULL, updated INTEGER NOT NULL);
            """);
        // Migración: bases creadas antes de existir la columna 'detail'.
        using (var c = _db.CreateCommand())
        {
            c.CommandText = "SELECT COUNT(*) FROM pragma_table_info('events') WHERE name='detail'";
            if (Convert.ToInt64(c.ExecuteScalar()) == 0) Exec("ALTER TABLE events ADD COLUMN detail TEXT");
        }
    }

    private long Now => _time.GetUtcNow().ToUnixTimeMilliseconds();

    private void Exec(string sql, Action<SqliteCommand>? bind = null)
    {
        using var c = _db.CreateCommand();
        c.CommandText = sql;
        bind?.Invoke(c);
        c.ExecuteNonQuery();
    }

    private long Scalar(string sql)
    {
        using var c = _db.CreateCommand();
        c.CommandText = sql;
        return Convert.ToInt64(c.ExecuteScalar());
    }

    public void AddEvent(SecurityEvent ev)
    {
        lock (_gate)
            Exec("INSERT OR REPLACE INTO events(id,ts,source,type,severity,actor,ip,target,detail) VALUES($id,$ts,$s,$t,$sev,$a,$ip,$tg,$d)", c =>
            {
                c.Parameters.AddWithValue("$id", ev.Id);
                c.Parameters.AddWithValue("$ts", ev.Timestamp.ToUnixTimeMilliseconds());
                c.Parameters.AddWithValue("$s", ev.Source);
                c.Parameters.AddWithValue("$t", ev.Type);
                c.Parameters.AddWithValue("$sev", (int)ev.Severity);
                c.Parameters.AddWithValue("$a", (object?)ev.Actor ?? DBNull.Value);
                c.Parameters.AddWithValue("$ip", (object?)ev.Ip ?? DBNull.Value);
                c.Parameters.AddWithValue("$tg", (object?)ev.Target ?? DBNull.Value);
                c.Parameters.AddWithValue("$d", (object?)ev.Detail ?? DBNull.Value);
            });
    }

    private static SecurityEvent ReadEvent(SqliteDataReader r) => new(
        r.GetString(0), DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(1)), r.GetString(2), r.GetString(3),
        (Severity)r.GetInt32(4),
        r.IsDBNull(5) ? null : r.GetString(5), r.IsDBNull(6) ? null : r.GetString(6), r.IsDBNull(7) ? null : r.GetString(7),
        r.IsDBNull(8) ? null : r.GetString(8));

    private const string EventCols = "id,ts,source,type,severity,actor,ip,target,detail";

    public SecurityEvent? GetEvent(string id)
    {
        lock (_gate)
        {
            using var c = _db.CreateCommand();
            c.CommandText = $"SELECT {EventCols} FROM events WHERE id=$id";
            c.Parameters.AddWithValue("$id", id);
            using var r = c.ExecuteReader();
            return r.Read() ? ReadEvent(r) : null;
        }
    }

    public IReadOnlyList<SecurityEvent> QueryEvents(DateTimeOffset? since = null, string? source = null, string? ip = null, int limit = 100)
    {
        lock (_gate)
        {
            using var c = _db.CreateCommand();
            c.CommandText = $"SELECT {EventCols} FROM events WHERE ($since IS NULL OR ts>=$since) AND ($src IS NULL OR source=$src) AND ($ip IS NULL OR ip=$ip) ORDER BY ts DESC LIMIT $lim";
            c.Parameters.AddWithValue("$since", since is null ? DBNull.Value : since.Value.ToUnixTimeMilliseconds());
            c.Parameters.AddWithValue("$src", (object?)source ?? DBNull.Value);
            c.Parameters.AddWithValue("$ip", (object?)ip ?? DBNull.Value);
            c.Parameters.AddWithValue("$lim", Math.Clamp(limit, 1, 10_000));
            using var r = c.ExecuteReader();
            var list = new List<SecurityEvent>();
            while (r.Read()) list.Add(ReadEvent(r));
            return list;
        }
    }

    public IReadOnlyList<Stored<SecurityEvent>> EventsAfter(long afterRowId, int limit)
    {
        lock (_gate)
        {
            using var c = _db.CreateCommand();
            c.CommandText = $"SELECT {EventCols},rowid FROM events WHERE rowid>$r ORDER BY rowid LIMIT $lim";
            c.Parameters.AddWithValue("$r", afterRowId);
            c.Parameters.AddWithValue("$lim", Math.Clamp(limit, 1, 10_000));
            using var r = c.ExecuteReader();
            var list = new List<Stored<SecurityEvent>>();
            while (r.Read()) list.Add(new(r.GetInt64(9), ReadEvent(r)));
            return list;
        }
    }

    public IReadOnlyList<Stored<Alert>> AlertsAfter(long afterRowId, int limit)
    {
        lock (_gate)
        {
            using var c = _db.CreateCommand();
            c.CommandText = $"SELECT {AlertCols},rowid FROM alerts WHERE rowid>$r ORDER BY rowid LIMIT $lim";
            c.Parameters.AddWithValue("$r", afterRowId);
            c.Parameters.AddWithValue("$lim", Math.Clamp(limit, 1, 10_000));
            using var r = c.ExecuteReader();
            var list = new List<Stored<Alert>>();
            while (r.Read()) list.Add(new(r.GetInt64(9), ReadAlert(r)));
            return list;
        }
    }

    public void AddBlock(BlockEntry b)
    {
        if (b.ExpiresAt <= b.CreatedAt)
            throw new ArgumentException("Todo bloqueo debe expirar después de crearse (principio 3).", nameof(b));
        lock (_gate)
            Exec("INSERT OR REPLACE INTO blocks(ip,rule_id,reason,created,expires) VALUES($ip,$r,$why,$c,$e)", c =>
            {
                c.Parameters.AddWithValue("$ip", b.Ip);
                c.Parameters.AddWithValue("$r", b.RuleId);
                c.Parameters.AddWithValue("$why", b.Reason);
                c.Parameters.AddWithValue("$c", b.CreatedAt.ToUnixTimeMilliseconds());
                c.Parameters.AddWithValue("$e", b.ExpiresAt.ToUnixTimeMilliseconds());
            });
    }

    public IReadOnlyList<BlockEntry> ListActiveBlocks()
    {
        lock (_gate)
        {
            using var c = _db.CreateCommand();
            c.CommandText = "SELECT ip,rule_id,reason,created,expires FROM blocks WHERE expires>$now ORDER BY created";
            c.Parameters.AddWithValue("$now", Now);
            using var r = c.ExecuteReader();
            var list = new List<BlockEntry>();
            while (r.Read())
                list.Add(new(r.GetString(0), r.GetString(1), r.GetString(2),
                    DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(3)), DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(4))));
            return list;
        }
    }

    public bool RemoveBlock(string ip)
    {
        lock (_gate)
        {
            using var c = _db.CreateCommand();
            c.CommandText = "DELETE FROM blocks WHERE ip=$ip";
            c.Parameters.AddWithValue("$ip", ip);
            return c.ExecuteNonQuery() > 0;
        }
    }

    private static BlockEntry ReadBlock(SqliteDataReader r) => new(r.GetString(0), r.GetString(1), r.GetString(2),
        DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(3)), DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(4)));

    public IReadOnlyList<BlockEntry> ListExpiredBlocks()
    {
        lock (_gate)
        {
            using var c = _db.CreateCommand();
            c.CommandText = "SELECT ip,rule_id,reason,created,expires FROM blocks WHERE expires<=$now ORDER BY expires";
            c.Parameters.AddWithValue("$now", Now);
            using var r = c.ExecuteReader();
            var list = new List<BlockEntry>();
            while (r.Read()) list.Add(ReadBlock(r));
            return list;
        }
    }

    public void AddAlert(Alert a)
    {
        lock (_gate)
            Exec("INSERT OR REPLACE INTO alerts(id,rule_id,ts,severity,group_key,message,event_ids,mode,action) VALUES($id,$r,$ts,$sev,$g,$m,$e,$mode,$act)", c =>
            {
                c.Parameters.AddWithValue("$id", a.Id);
                c.Parameters.AddWithValue("$r", a.RuleId);
                c.Parameters.AddWithValue("$ts", a.Timestamp.ToUnixTimeMilliseconds());
                c.Parameters.AddWithValue("$sev", (int)a.Severity);
                c.Parameters.AddWithValue("$g", (object?)a.GroupKey ?? DBNull.Value);
                c.Parameters.AddWithValue("$m", a.Message);
                c.Parameters.AddWithValue("$e", string.Join(',', a.EventIds));
                c.Parameters.AddWithValue("$mode", a.Mode.ToString());
                c.Parameters.AddWithValue("$act", (object?)a.ActionTaken ?? DBNull.Value);
            });
    }

    private const string AlertCols = "id,rule_id,ts,severity,group_key,message,event_ids,mode,action";

    private static Alert ReadAlert(SqliteDataReader r) => new(
        r.GetString(0), r.GetString(1), DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(2)), (Severity)r.GetInt32(3),
        r.IsDBNull(4) ? null : r.GetString(4), r.GetString(5),
        r.GetString(6).Length == 0 ? Array.Empty<string>() : r.GetString(6).Split(','),
        Enum.Parse<RuleMode>(r.GetString(7)), r.IsDBNull(8) ? null : r.GetString(8));

    public Alert? GetAlert(string id)
    {
        lock (_gate)
        {
            using var c = _db.CreateCommand();
            c.CommandText = $"SELECT {AlertCols} FROM alerts WHERE id=$id";
            c.Parameters.AddWithValue("$id", id);
            using var r = c.ExecuteReader();
            return r.Read() ? ReadAlert(r) : null;
        }
    }

    public IReadOnlyList<Alert> ListAlerts(DateTimeOffset? since = null, string? ruleId = null, Severity? minSeverity = null, int limit = 100)
    {
        lock (_gate)
        {
            using var c = _db.CreateCommand();
            c.CommandText = $"SELECT {AlertCols} FROM alerts WHERE ($since IS NULL OR ts>=$since) AND ($rule IS NULL OR rule_id=$rule) AND ($sev IS NULL OR severity>=$sev) ORDER BY ts DESC LIMIT $lim";
            c.Parameters.AddWithValue("$since", since is null ? DBNull.Value : since.Value.ToUnixTimeMilliseconds());
            c.Parameters.AddWithValue("$rule", (object?)ruleId ?? DBNull.Value);
            c.Parameters.AddWithValue("$sev", minSeverity is null ? DBNull.Value : (int)minSeverity.Value);
            c.Parameters.AddWithValue("$lim", Math.Clamp(limit, 1, 10_000));
            using var r = c.ExecuteReader();
            var list = new List<Alert>();
            while (r.Read()) list.Add(ReadAlert(r));
            return list;
        }
    }

    /// <summary>Resumen de solo lectura para diagnóstico (--stats): qué entra, qué alerta y hasta dónde llegó cada collector.</summary>
    public IReadOnlyList<string> Diagnostics()
    {
        var lines = new List<string>();
        lock (_gate)
        {
            void Query(string title, string sql, Func<SqliteDataReader, string> row)
            {
                lines.Add(title);
                using var c = _db.CreateCommand();
                c.CommandText = sql;
                using var r = c.ExecuteReader();
                var any = false;
                while (r.Read()) { any = true; lines.Add("  " + row(r)); }
                if (!any) lines.Add("  (vacío)");
            }
            Query("Eventos por fuente y tipo (los 40 más frecuentes):", "SELECT source,type,COUNT(*) FROM events GROUP BY source,type ORDER BY 3 DESC LIMIT 40",
                r => $"{r.GetString(0),-20} {r.GetString(1),-14} {r.GetInt64(2)}");
            Query("Alertas por regla:", "SELECT rule_id,COUNT(*),MAX(ts) FROM alerts GROUP BY rule_id ORDER BY rule_id",
                r => $"{r.GetString(0),-16} {r.GetInt64(1)} (última: {DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(2)):u})");
            Query("Bloqueos:", "SELECT ip,rule_id,expires FROM blocks ORDER BY created",
                r => $"{r.GetString(0)}  {r.GetString(1)}  expira {DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(2)):u}");
            Query("Cursores de los collectors:", "SELECT name,value FROM cursors ORDER BY name", r => $"{r.GetString(0)} = {r.GetInt64(1)}");
        }
        return lines;
    }

    public long? GetCursor(string name)
    {
        lock (_gate)
        {
            using var c = _db.CreateCommand();
            c.CommandText = "SELECT value FROM cursors WHERE name=$n";
            c.Parameters.AddWithValue("$n", name);
            return c.ExecuteScalar() is long v ? v : null;
        }
    }

    public void SetCursor(string name, long value)
    {
        lock (_gate)
            Exec("INSERT OR REPLACE INTO cursors(name,value) VALUES($n,$v)", c =>
            {
                c.Parameters.AddWithValue("$n", name);
                c.Parameters.AddWithValue("$v", value);
            });
    }

    public void SetAudit(AuditEntry a)
    {
        lock (_gate)
            Exec("INSERT OR REPLACE INTO audits(kind,status,ts,summary) VALUES($k,$s,$t,$m)", c =>
            {
                c.Parameters.AddWithValue("$k", a.Kind);
                c.Parameters.AddWithValue("$s", a.Status);
                c.Parameters.AddWithValue("$t", a.CheckedAt.ToUnixTimeMilliseconds());
                c.Parameters.AddWithValue("$m", a.Summary);
            });
    }

    public AuditEntry? GetAudit(string kind)
    {
        lock (_gate)
        {
            using var c = _db.CreateCommand();
            c.CommandText = "SELECT kind,status,ts,summary FROM audits WHERE kind=$k";
            c.Parameters.AddWithValue("$k", kind);
            using var r = c.ExecuteReader();
            return r.Read() ? new(r.GetString(0), r.GetString(1), DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(2)), r.GetString(3)) : null;
        }
    }

    public RuleMode GetRuleMode(string ruleId)
    {
        lock (_gate)
        {
            using var c = _db.CreateCommand();
            c.CommandText = "SELECT mode FROM rule_state WHERE rule_id=$id";
            c.Parameters.AddWithValue("$id", ruleId);
            return c.ExecuteScalar() is string m && Enum.TryParse<RuleMode>(m, out var mode) ? mode : RuleMode.Observe;
        }
    }

    public void SetRuleMode(string ruleId, RuleMode mode)
    {
        lock (_gate)
            Exec("INSERT OR REPLACE INTO rule_state(rule_id,mode,updated) VALUES($id,$m,$u)", c =>
            {
                c.Parameters.AddWithValue("$id", ruleId);
                c.Parameters.AddWithValue("$m", mode.ToString());
                c.Parameters.AddWithValue("$u", Now);
            });
    }

    /// <summary>Bytes realmente ocupados por datos (excluye páginas libres).</summary>
    public long UsedBytes
    {
        get
        {
            lock (_gate)
                return (Scalar("PRAGMA page_count;") - Scalar("PRAGMA freelist_count;")) * Scalar("PRAGMA page_size;");
        }
    }

    public int EventCount { get { lock (_gate) return (int)Scalar("SELECT COUNT(*) FROM events"); } }

    public PurgeResult Purge()
    {
        lock (_gate)
        {
            int events = 0, blocks = 0;
            // Los bloqueos vencidos NO se purgan por antigüedad: solo se borran cuando el responder confirma que retiró la regla del
            // firewall (SweepExpired / --unblock-ip). Borrarlos antes dejaría una regla de firewall huérfana y permanente.
            // 1) retención por antigüedad
            using (var c = _db.CreateCommand())
            {
                c.CommandText = "DELETE FROM events WHERE ts<$cut";
                c.Parameters.AddWithValue("$cut", _time.GetUtcNow().Subtract(_opt.EventRetention).ToUnixTimeMilliseconds());
                events += c.ExecuteNonQuery();
            }
            // 1b) cuota por fuente: ninguna fuente puede ocupar todo el espacio
            using (var c = _db.CreateCommand())
            {
                c.CommandText = @"DELETE FROM events WHERE id IN (
                    SELECT id FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY source ORDER BY ts DESC, id DESC) AS rn FROM events) WHERE rn > $max)";
                c.Parameters.AddWithValue("$max", _opt.MaxEventsPerSource);
                events += c.ExecuteNonQuery();
            }
            // 2) tope de cantidad
            using (var c = _db.CreateCommand())
            {
                c.CommandText = "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY ts ASC LIMIT MAX(0,(SELECT COUNT(*) FROM events)-$max))";
                c.Parameters.AddWithValue("$max", _opt.MaxEvents);
                events += c.ExecuteNonQuery();
            }
            // alertas: misma retención y tope propio
            using (var c = _db.CreateCommand())
            {
                c.CommandText = "DELETE FROM alerts WHERE ts<$cut";
                c.Parameters.AddWithValue("$cut", _time.GetUtcNow().Subtract(_opt.EventRetention).ToUnixTimeMilliseconds());
                c.ExecuteNonQuery();
            }
            using (var c = _db.CreateCommand())
            {
                c.CommandText = "DELETE FROM alerts WHERE id IN (SELECT id FROM alerts ORDER BY ts ASC LIMIT MAX(0,(SELECT COUNT(*) FROM alerts)-$max))";
                c.Parameters.AddWithValue("$max", _opt.MaxAlerts);
                c.ExecuteNonQuery();
            }
            // 3) tope de tamaño: borrar lotes de los más antiguos de la fuente más grande hasta caber (no la evidencia de las demás)
            while (UsedBytes > _opt.MaxDatabaseBytes && Scalar("SELECT COUNT(*) FROM events") > 0)
            {
                using var c = _db.CreateCommand();
                c.CommandText = @"DELETE FROM events WHERE id IN (
                    SELECT id FROM events
                    WHERE source = (SELECT source FROM events GROUP BY source ORDER BY COUNT(*) DESC LIMIT 1)
                    ORDER BY ts ASC
                    LIMIT MAX(1,(SELECT COUNT(*) FROM events WHERE source = (SELECT source FROM events GROUP BY source ORDER BY COUNT(*) DESC LIMIT 1))/10))";
                events += c.ExecuteNonQuery();
                Exec("PRAGMA incremental_vacuum;");
            }
            Exec("PRAGMA incremental_vacuum;");
            return new PurgeResult(events, blocks);
        }
    }

    public void Dispose() => _db.Dispose();
}
