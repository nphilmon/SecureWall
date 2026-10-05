using System.Text.Json;
using System.Text.Json.Serialization;
using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Models;

namespace SecureWall.Infrastructure.Configuration;

/// <summary>Réglages persistés dans la table Settings (clé "app.settings"), sans aucun secret.</summary>
public sealed class SettingsStore : ISettingsStore
{
    const string Key = "app.settings";
    static readonly JsonSerializerOptions Json = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };

    readonly ISecurityStore _store;
    public AppSettings Current { get; private set; }
    public event Action? Changed;

    public SettingsStore(ISecurityStore store)
    {
        _store = store;
        Current = Load();
        if (Current.Schedules.Count == 0)
        {
            Current.Schedules = DefaultSchedules();
            Save();
        }
    }

    AppSettings Load()
    {
        try
        {
            var raw = _store.GetSetting(Key);
            if (raw != null) return Sanitize(JsonSerializer.Deserialize<AppSettings>(raw, Json) ?? new());
        }
        catch { /* réglages corrompus : valeurs par défaut */ }
        return new();
    }

    public void Save()
    {
        Current = Sanitize(Current);
        _store.SetSetting(Key, JsonSerializer.Serialize(Current, Json));
        Changed?.Invoke();
    }

    public string ExportJson() => JsonSerializer.Serialize(Current, Json);

    public OperationResult ImportJson(string json)
    {
        try
        {
            var s = JsonSerializer.Deserialize<AppSettings>(json, Json);
            if (s == null) return OperationResult.Fail("Fichier de réglages vide.");
            Current = Sanitize(s);
            Save();
            return OperationResult.Ok("Réglages importés.");
        }
        catch (Exception ex) { return OperationResult.Fail("Fichier de réglages invalide : " + ex.Message); }
    }

    static AppSettings Sanitize(AppSettings s)
    {
        s.RefreshSeconds = Math.Clamp(s.RefreshSeconds, 1, 60);
        s.RetentionDays = Math.Clamp(s.RetentionDays, 7, 3650);
        s.SignatureMaxAgeDays = Math.Clamp(s.SignatureMaxAgeDays, 1, 30);
        s.Schedules ??= new();
        foreach (var sc in s.Schedules)
        {
            if (!TimeOnly.TryParseExact(sc.Time, "HH:mm", out _)) sc.Time = "12:00";
            sc.DayOfMonth = Math.Clamp(sc.DayOfMonth, 1, 28);
        }
        return s;
    }

    public static List<ScheduleConfig> DefaultSchedules() => new()
    {
        new() { Id = "Quick", Label = "Analyse rapide quotidienne", Frequency = ScheduleFrequency.Daily, Time = "12:00", ScanKind = ScanKind.Quick },
        new() { Id = "Weekly", Label = "Analyse hebdomadaire", Frequency = ScheduleFrequency.Weekly, DayOfWeek = DayOfWeek.Sunday, Time = "18:00", ScanKind = ScanKind.Quick },
        new() { Id = "Full", Label = "Analyse complète mensuelle", Frequency = ScheduleFrequency.Monthly, DayOfMonth = 1, Time = "20:00", ScanKind = ScanKind.Full },
        new() { Id = "Custom", Label = "Analyse personnalisée", Frequency = ScheduleFrequency.Weekly, DayOfWeek = DayOfWeek.Saturday, Time = "10:00", ScanKind = ScanKind.Custom },
    };
}
