#ifndef NETLENS_HOSTTABLE_H
#define NETLENS_HOSTTABLE_H

#include <windows.h>
#include <commctrl.h>

namespace nl {

// Wraps a SysListView32 in LVS_OWNERDATA (virtual) mode with custom-draw
// status dot, alt-row tinting, blue selection, and colored service badges.
namespace HostTable {

enum Column : int {
    COL_IP = 0,
    COL_MAC,
    COL_STATUS,
    COL_HOSTNAME,
    COL_DEVICE,
    COL_VENDOR,
    COL_OPEN_PORTS,
    COL_SERVICES,
    COL_RTT,
    COL_COUNT
};

HWND    Create(HWND parent, HINSTANCE hInst, int id);
void    RefreshData(HWND hLv);
void    OnGetDispInfo(HWND hLv, NMLVDISPINFOW* p);
LRESULT OnCustomDraw(HWND hLv, NMLVCUSTOMDRAW* p);

// User clicked a column header — translate to App sort + update arrows.
void    OnColumnClick(HWND hLv, int column);

// Refresh the sort-arrow indicator (header item HDF_SORTUP / HDF_SORTDOWN).
void    UpdateSortIndicator(HWND hLv);

// Show / hide the Status column (used when "View offline hosts" toggles).
void    SetStatusColumnVisible(HWND hLv, bool visible);

// Redistribute column widths based on the listview's current client width.
// Fixed widths for IP/MAC/Status/Hostname/Device/Vendor/OpenPorts/RTT,
// Services flexes to fill. Call after the listview is resized.
void    AutoSizeColumns(HWND hLv);

}  // namespace HostTable
}  // namespace nl

#endif // NETLENS_HOSTTABLE_H
