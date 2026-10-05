using System.Windows.Forms;
using DrawingIcon = System.Drawing.Icon;

namespace SecureWall.Infrastructure.Notifications;

/// <summary>Icône de la zone de notification (NotifyIcon) et son menu contextuel.</summary>
public sealed class TrayIconHost : IDisposable
{
    readonly NotifyIcon _icon;
    readonly ContextMenuStrip _menu = new();
    Action? _balloonClick;

    public event Action? DoubleClicked;

    public TrayIconHost(DrawingIcon icon, string tooltip)
    {
        _icon = new NotifyIcon { Icon = icon, Text = tooltip.Length > 63 ? tooltip[..63] : tooltip, ContextMenuStrip = _menu, Visible = true };
        _icon.DoubleClick += (_, _) => DoubleClicked?.Invoke();
        _icon.BalloonTipClicked += (_, _) => _balloonClick?.Invoke();
    }

    public ToolStripMenuItem AddItem(string text, Action onClick, bool enabled = true)
    {
        var item = new ToolStripMenuItem(text) { Enabled = enabled };
        item.Click += (_, _) => onClick();
        _menu.Items.Add(item);
        return item;
    }

    public void AddHeader(string text) => _menu.Items.Add(new ToolStripMenuItem(text) { Enabled = false });
    public void AddSeparator() => _menu.Items.Add(new ToolStripSeparator());

    public void SetTooltip(string text) => _icon.Text = text.Length > 63 ? text[..63] : text;

    public void ShowBalloon(string title, string message, Action? onClick = null)
    {
        _balloonClick = onClick;
        _icon.ShowBalloonTip(6000, title, message, ToolTipIcon.Info);
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
        _menu.Dispose();
    }
}
