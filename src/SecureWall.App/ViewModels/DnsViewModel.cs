using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureWall.App.Services;
using SecureWall.Core.DTOs;
using SecureWall.Core.Enums;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Logic;
using SecureWall.Security.DnsConfig;

namespace SecureWall.App.ViewModels;

public sealed record DnsServerLine(string Address, string Description, bool Unusual)
{
    public Level Level => Unusual ? Level.Warning : Level.Neutral;
}

/// <summary>Une carte réseau active et son état DNS, avec les saisies de l'utilisateur (serveur prédéfini ou personnalisé).</summary>
public sealed partial class DnsAdapterItem : ObservableObject
{
    public DnsAdapterInfo Info { get; }
    public string Title => $"{Info.Name} · {Info.Kind}";
    public string Description => Info.Description;
    public string ModeText => Info.ModeText;
    public IReadOnlyList<DnsServerLine> Servers { get; }
    public bool HasServers => Servers.Count > 0;
    public bool HasUnusual => Servers.Any(s => s.Unusual);
    public bool IsManual => Info.IsManual;

    [ObservableProperty] private int _presetIndex;
    [ObservableProperty] private string _custom = "";

    public string PresetDescription => DnsLogic.Presets[Math.Clamp(PresetIndex, 0, DnsLogic.Presets.Length - 1)] is var p ? $"{p.ServersText} — {p.Description}" : "";
    partial void OnPresetIndexChanged(int value) => OnPropertyChanged(nameof(PresetDescription));

    public DnsAdapterItem(DnsAdapterInfo info)
    {
        Info = info;
        Servers = info.Servers.Select(s => new DnsServerLine(s, DnsLogic.Describe(s), DnsLogic.IsUnusual(s))).ToList();
    }
}

public sealed partial class DnsViewModel : PageViewModel
{
    readonly DnsService _dns;
    readonly IPrivilegedClient _client;
    readonly IDialogService _dialogs;

    public override string Title => "DNS";
    public override string Subtitle => "Serveurs DNS de chaque carte réseau : les voir, les changer ou revenir à la configuration automatique.";

    public ObservableCollection<DnsAdapterItem> Adapters { get; } = new();
    public static string[] PresetNames { get; } = DnsLogic.Presets.Select(p => p.Name).ToArray();

    [ObservableProperty] private bool _serviceAvailable;

    public DnsViewModel(DnsService dns, IPrivilegedClient client, IDialogService dialogs) { _dns = dns; _client = client; _dialogs = dialogs; }

    public override Task OnNavigatedToAsync() => GuardAsync(LoadAsync, "Chargement des serveurs DNS");

    async Task LoadAsync()
    {
        ServiceAvailable = await _client.IsAvailableAsync(PageToken);
        var list = await _dns.GetAdaptersAsync(PageToken);
        // Conserve les saisies en cours des cartes déjà affichées.
        var old = Adapters.ToDictionary(a => a.Info.Index);
        Adapters.Clear();
        foreach (var info in list.OrderByDescending(a => a.Servers.Count > 0).ThenBy(a => a.Name))   // cartes virtuelles sans DNS en dernier
        {
            var item = new DnsAdapterItem(info);
            if (old.TryGetValue(info.Index, out var prev)) { item.PresetIndex = prev.PresetIndex; item.Custom = prev.Custom; }
            Adapters.Add(item);
        }
        if (Adapters.Count == 0) Info("Aucune carte réseau active.");
        else if (!ServiceAvailable) Warn("Le service privilégié est arrêté : vous pouvez consulter les serveurs DNS mais pas les modifier.");
        else Message = "";
    }

    [RelayCommand] Task RefreshAsync() => GuardAsync(LoadAsync, "Actualisation des serveurs DNS");

    [RelayCommand]
    Task ApplyPresetAsync(DnsAdapterItem? item)
    {
        if (item == null) return Task.CompletedTask;
        var p = DnsLogic.Presets[Math.Clamp(item.PresetIndex, 0, DnsLogic.Presets.Length - 1)];
        return ApplyAsync(item, string.Join(",", p.Servers), p.Name);
    }

    [RelayCommand]
    Task ApplyCustomAsync(DnsAdapterItem? item)
    {
        if (item == null) return Task.CompletedTask;
        if (!DnsLogic.TryParseServers(item.Custom, out var servers, out var error)) { Fail(error); return Task.CompletedTask; }
        return ApplyAsync(item, string.Join(",", servers), "serveurs personnalisés");
    }

    async Task ApplyAsync(DnsAdapterItem item, string servers, string label)
    {
        var current = item.Info.Servers.Count == 0 ? "aucun" : string.Join(", ", item.Info.Servers);
        if (!_dialogs.Confirm("Changer les serveurs DNS",
                $"Carte « {item.Info.Name} »\nActuellement : {current}\nNouveaux serveurs ({label}) : {servers.Replace(",", ", ")}\n\n" +
                "Le DNS traduit les noms de sites en adresses : le fournisseur choisi verra les noms des sites que vous consultez. " +
                "Vous pourrez revenir à la configuration automatique à tout moment.", "Appliquer")) return;
        await RunAsync(async () =>
        {
            var r = await _dns.SetServersAsync(item.Info, servers);
            if (r.Success) { await _dns.FlushCacheAsync(); Success(r.Message); } else Fail(r.Message);
        });
    }

    [RelayCommand]
    async Task ResetAsync(DnsAdapterItem? item)
    {
        if (item == null) return;
        if (!_dialogs.Confirm("Revenir au DNS automatique",
                $"La carte « {item.Info.Name} » utilisera de nouveau les serveurs DNS fournis par votre réseau (box, routeur, entreprise).", "Revenir en automatique")) return;
        await RunAsync(async () =>
        {
            var r = await _dns.ResetAsync(item.Info);
            if (r.Success) { await _dns.FlushCacheAsync(); Success(r.Message); } else Fail(r.Message);
        });
    }

    [RelayCommand]
    Task FlushAsync() => RunAsync(async () =>
    {
        var r = await _dns.FlushCacheAsync();
        if (r.Success) Success(r.Message); else Fail(r.Message);
    }, reload: false);

    async Task RunAsync(Func<Task> action, bool reload = true)
    {
        await GuardAsync(async () =>
        {
            await action();
            if (reload)
            {
                var msg = Message; var lvl = MessageLevel;
                await LoadAsync();
                Message = msg; MessageLevel = lvl;     // LoadAsync efface le message : on garde le résultat de l'opération
            }
        }, "Gestion DNS");
    }
}
