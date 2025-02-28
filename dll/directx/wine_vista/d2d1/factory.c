/*
 * Copyright 2014 Henri Verbeet for CodeWeavers
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <config.h>
#include "wine/port.h"

#define D2D1_INIT_GUID
#include "d2d1_private.h"

WINE_DECLARE_DEBUG_CHANNEL(winediag);
WINE_DEFAULT_DEBUG_CHANNEL(d2d);

struct d2d_settings d2d_settings =
{
    ~0u,    /* No ID2D1Factory version limit by default. */
};

struct d2d_factory
{
    ID2D1Factory1 ID2D1Factory1_iface;
    LONG refcount;

    ID3D10Device1 *device;

    float dpi_x;
    float dpi_y;
};

static inline struct d2d_factory *impl_from_ID2D1Factory1(ID2D1Factory1 *iface)
{
    return CONTAINING_RECORD(iface, struct d2d_factory, ID2D1Factory1_iface);
}

static HRESULT d2d_factory_reload_sysmetrics(struct d2d_factory *factory)
{
    HDC hdc;

    if (!(hdc = GetDC(NULL)))
    {
        factory->dpi_x = factory->dpi_y = 96.0f;
        return E_FAIL;
    }

    factory->dpi_x = GetDeviceCaps(hdc, LOGPIXELSX);
    factory->dpi_y = GetDeviceCaps(hdc, LOGPIXELSY);

    ReleaseDC(NULL, hdc);

    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_QueryInterface(ID2D1Factory1 *iface, REFIID iid, void **out)
{
    TRACE("iface %p, iid %s, out %p.\n", iface, debugstr_guid(iid), out);

    if ((IsEqualGUID(iid, &IID_ID2D1Factory1) && d2d_settings.max_version_factory >= 1)
            || IsEqualGUID(iid, &IID_ID2D1Factory)
            || IsEqualGUID(iid, &IID_IUnknown))
    {
        ID2D1Factory1_AddRef(iface);
        *out = iface;
        return S_OK;
    }

    WARN("%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid));

    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE d2d_factory_AddRef(ID2D1Factory1 *iface)
{
    struct d2d_factory *factory = impl_from_ID2D1Factory1(iface);
    ULONG refcount = InterlockedIncrement(&factory->refcount);

    TRACE("%p increasing refcount to %u.\n", iface, refcount);

    return refcount;
}

static ULONG STDMETHODCALLTYPE d2d_factory_Release(ID2D1Factory1 *iface)
{
    struct d2d_factory *factory = impl_from_ID2D1Factory1(iface);
    ULONG refcount = InterlockedDecrement(&factory->refcount);

    TRACE("%p decreasing refcount to %u.\n", iface, refcount);

    if (!refcount)
    {
        if (factory->device)
            ID3D10Device1_Release(factory->device);
        heap_free(factory);
    }

    return refcount;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_ReloadSystemMetrics(ID2D1Factory1 *iface)
{
    struct d2d_factory *factory = impl_from_ID2D1Factory1(iface);

    TRACE("iface %p.\n", iface);

    return d2d_factory_reload_sysmetrics(factory);
}

static void STDMETHODCALLTYPE d2d_factory_GetDesktopDpi(ID2D1Factory1 *iface, float *dpi_x, float *dpi_y)
{
    struct d2d_factory *factory = impl_from_ID2D1Factory1(iface);

    TRACE("iface %p, dpi_x %p, dpi_y %p.\n", iface, dpi_x, dpi_y);

    *dpi_x = factory->dpi_x;
    *dpi_y = factory->dpi_y;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_CreateRectangleGeometry(ID2D1Factory1 *iface,
        const D2D1_RECT_F *rect, ID2D1RectangleGeometry **geometry)
{
    struct d2d_geometry *object;
    HRESULT hr;

    TRACE("iface %p, rect %s, geometry %p.\n", iface, debug_d2d_rect_f(rect), geometry);

    if (!(object = heap_alloc_zero(sizeof(*object))))
        return E_OUTOFMEMORY;

    if (FAILED(hr = d2d_rectangle_geometry_init(object, (ID2D1Factory *)iface, rect)))
    {
        WARN("Failed to initialize rectangle geometry, hr %#x.\n", hr);
        heap_free(object);
        return hr;
    }

    TRACE("Created rectangle geometry %p.\n", object);
    *geometry = (ID2D1RectangleGeometry *)&object->ID2D1Geometry_iface;

    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_CreateRoundedRectangleGeometry(ID2D1Factory1 *iface,
        const D2D1_ROUNDED_RECT *rect, ID2D1RoundedRectangleGeometry **geometry)
{
    FIXME("iface %p, rect %p, geometry %p stub!\n", iface, rect, geometry);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_CreateEllipseGeometry(ID2D1Factory1 *iface,
        const D2D1_ELLIPSE *ellipse, ID2D1EllipseGeometry **geometry)
{
    FIXME("iface %p, ellipse %p, geometry %p stub!\n", iface, ellipse, geometry);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_CreateGeometryGroup(ID2D1Factory1 *iface,
        D2D1_FILL_MODE fill_mode, ID2D1Geometry **geometries, UINT32 geometry_count, ID2D1GeometryGroup **group)
{
    FIXME("iface %p, fill_mode %#x, geometries %p, geometry_count %u, group %p stub!\n",
            iface, fill_mode, geometries, geometry_count, group);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_CreateTransformedGeometry(ID2D1Factory1 *iface,
        ID2D1Geometry *src_geometry, const D2D1_MATRIX_3X2_F *transform,
        ID2D1TransformedGeometry **transformed_geometry)
{
    struct d2d_geometry *object;

    TRACE("iface %p, src_geometry %p, transform %p, transformed_geometry %p.\n",
            iface, src_geometry, transform, transformed_geometry);

    if (!(object = heap_alloc_zero(sizeof(*object))))
        return E_OUTOFMEMORY;

    d2d_transformed_geometry_init(object, (ID2D1Factory *)iface, src_geometry, transform);

    TRACE("Created transformed geometry %p.\n", object);
    *transformed_geometry = (ID2D1TransformedGeometry *)&object->ID2D1Geometry_iface;

    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_CreatePathGeometry(ID2D1Factory1 *iface, ID2D1PathGeometry **geometry)
{
    struct d2d_geometry *object;

    TRACE("iface %p, geometry %p.\n", iface, geometry);

    if (!(object = heap_alloc_zero(sizeof(*object))))
        return E_OUTOFMEMORY;

    d2d_path_geometry_init(object, (ID2D1Factory *)iface);

    TRACE("Created path geometry %p.\n", object);
    *geometry = (ID2D1PathGeometry *)&object->ID2D1Geometry_iface;

    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_CreateStrokeStyle(ID2D1Factory1 *iface,
        const D2D1_STROKE_STYLE_PROPERTIES *desc, const float *dashes, UINT32 dash_count,
        ID2D1StrokeStyle **stroke_style)
{
    struct d2d_stroke_style *object;
    HRESULT hr;

    TRACE("iface %p, desc %p, dashes %p, dash_count %u, stroke_style %p.\n",
            iface, desc, dashes, dash_count, stroke_style);

    if (!(object = heap_alloc_zero(sizeof(*object))))
        return E_OUTOFMEMORY;

    if (FAILED(hr = d2d_stroke_style_init(object, (ID2D1Factory *)iface, desc, dashes, dash_count)))
    {
        WARN("Failed to initialize stroke style, hr %#x.\n", hr);
        heap_free(object);
        return hr;
    }

    TRACE("Created stroke style %p.\n", object);
    *stroke_style = &object->ID2D1StrokeStyle_iface;

    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_CreateDrawingStateBlock(ID2D1Factory1 *iface,
        const D2D1_DRAWING_STATE_DESCRIPTION *desc, IDWriteRenderingParams *text_rendering_params,
        ID2D1DrawingStateBlock **state_block)
{
    struct d2d_state_block *object;

    TRACE("iface %p, desc %p, text_rendering_params %p, state_block %p.\n",
            iface, desc, text_rendering_params, state_block);

    if (!(object = heap_alloc_zero(sizeof(*object))))
        return E_OUTOFMEMORY;

    d2d_state_block_init(object, (ID2D1Factory *)iface, desc, text_rendering_params);

    TRACE("Created state block %p.\n", object);
    *state_block = &object->ID2D1DrawingStateBlock_iface;

    return S_OK;
}

static HRESULT d2d_factory_get_device(struct d2d_factory *factory, ID3D10Device1 **device)
{
    HRESULT hr = S_OK;

    if (!factory->device && FAILED(hr = D3D10CreateDevice1(NULL, D3D10_DRIVER_TYPE_HARDWARE, NULL, D3D10_CREATE_DEVICE_BGRA_SUPPORT,
            D3D10_FEATURE_LEVEL_10_0, D3D10_1_SDK_VERSION, &factory->device)))
        WARN("Failed to create device, hr %#x.\n", hr);

    *device = factory->device;
    return hr;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_CreateWicBitmapRenderTarget(ID2D1Factory1 *iface,
        IWICBitmap *target, const D2D1_RENDER_TARGET_PROPERTIES *desc, ID2D1RenderTarget **render_target)
{
    struct d2d_factory *factory = impl_from_ID2D1Factory1(iface);
    struct d2d_wic_render_target *object;
    ID3D10Device1 *device;
    HRESULT hr;

    TRACE("iface %p, target %p, desc %p, render_target %p.\n", iface, target, desc, render_target);

    if (!(object = heap_alloc_zero(sizeof(*object))))
        return E_OUTOFMEMORY;

    if (FAILED(hr = d2d_factory_get_device(factory, &device)))
    {
        heap_free(object);
        return hr;
    }

    if (FAILED(hr = d2d_wic_render_target_init(object, (ID2D1Factory *)iface, device, target, desc)))
    {
        WARN("Failed to initialize render target, hr %#x.\n", hr);
        heap_free(object);
        return hr;
    }

    TRACE("Created render target %p.\n", object);
    *render_target = &object->ID2D1RenderTarget_iface;

    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_CreateHwndRenderTarget(ID2D1Factory1 *iface,
        const D2D1_RENDER_TARGET_PROPERTIES *desc, const D2D1_HWND_RENDER_TARGET_PROPERTIES *hwnd_rt_desc,
        ID2D1HwndRenderTarget **render_target)
{
    struct d2d_factory *factory = impl_from_ID2D1Factory1(iface);
    struct d2d_hwnd_render_target *object;
    ID3D10Device1 *device;
    HRESULT hr;

    TRACE("iface %p, desc %p, hwnd_rt_desc %p, render_target %p.\n", iface, desc, hwnd_rt_desc, render_target);

    if (FAILED(hr = d2d_factory_get_device(factory, &device)))
        return hr;

    if (!(object = heap_alloc_zero(sizeof(*object))))
        return E_OUTOFMEMORY;

    if (FAILED(hr = d2d_hwnd_render_target_init(object, (ID2D1Factory *)iface, device, desc, hwnd_rt_desc)))
    {
        WARN("Failed to initialize render target, hr %#x.\n", hr);
        heap_free(object);
        return hr;
    }

    TRACE("Created render target %p.\n", object);
    *render_target = &object->ID2D1HwndRenderTarget_iface;

    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_CreateDxgiSurfaceRenderTarget(ID2D1Factory1 *iface,
        IDXGISurface *surface, const D2D1_RENDER_TARGET_PROPERTIES *desc, ID2D1RenderTarget **render_target)
{
    TRACE("iface %p, surface %p, desc %p, render_target %p.\n", iface, surface, desc, render_target);

    return d2d_d3d_create_render_target((ID2D1Factory *)iface, surface, NULL, desc, render_target);
}

static HRESULT STDMETHODCALLTYPE d2d_factory_CreateDCRenderTarget(ID2D1Factory1 *iface,
        const D2D1_RENDER_TARGET_PROPERTIES *desc, ID2D1DCRenderTarget **render_target)
{
    struct d2d_factory *factory = impl_from_ID2D1Factory1(iface);
    struct d2d_dc_render_target *object;
    ID3D10Device1 *device;
    HRESULT hr;

    TRACE("iface %p, desc %p, render_target %p.\n", iface, desc, render_target);

    if (FAILED(hr = d2d_factory_get_device(factory, &device)))
        return hr;

    if (!(object = heap_alloc_zero(sizeof(*object))))
        return E_OUTOFMEMORY;

    if (FAILED(hr = d2d_dc_render_target_init(object, (ID2D1Factory *)iface, device, desc)))
    {
        WARN("Failed to initialize render target, hr %#x.\n", hr);
        heap_free(object);
        return hr;
    }

    TRACE("Created render target %p.\n", object);
    *render_target = &object->ID2D1DCRenderTarget_iface;

    return S_OK;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_CreateDevice(ID2D1Factory1 *iface,
        IDXGIDevice *dxgi_device, ID2D1Device **device)
{
    FIXME("iface %p, dxgi_device %p, device %p stub!\n", iface, dxgi_device, device);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_CreateStrokeStyle1(ID2D1Factory1 *iface,
        const D2D1_STROKE_STYLE_PROPERTIES1 *desc, const float *dashes, UINT32 dash_count,
        ID2D1StrokeStyle1 **stroke_style)
{
    FIXME("iface %p, desc %p, dashes %p, dash_count %u, stroke_style %p stub!\n",
            iface, desc, dashes, dash_count, stroke_style);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_CreatePathGeometry1(ID2D1Factory1 *iface, ID2D1PathGeometry1 **geometry)
{
    FIXME("iface %p, geometry %p stub!\n", iface, geometry);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_CreateDrawingStateBlock1(ID2D1Factory1 *iface,
        const D2D1_DRAWING_STATE_DESCRIPTION1 *desc, IDWriteRenderingParams *text_rendering_params,
        ID2D1DrawingStateBlock1 **state_block)
{
    FIXME("iface %p, desc %p, text_rendering_params %p, state_block %p stub!\n",
            iface, desc, text_rendering_params, state_block);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_CreateGdiMetafile(ID2D1Factory1 *iface,
        IStream *stream, ID2D1GdiMetafile **metafile)
{
    FIXME("iface %p, stream %p, metafile %p stub!\n", iface, stream, metafile);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_RegisterEffectFromStream(ID2D1Factory1 *iface,
        REFCLSID effect_id, IStream *property_xml, const D2D1_PROPERTY_BINDING *bindings,
        UINT32 binding_count, PD2D1_EFFECT_FACTORY effect_factory)
{
    FIXME("iface %p, effect_id %s, property_xml %p, bindings %p, binding_count %u, effect_factory %p stub!\n",
            iface, debugstr_guid(effect_id), property_xml, bindings, binding_count, effect_factory);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_RegisterEffectFromString(ID2D1Factory1 *iface,
        REFCLSID effect_id, const WCHAR *property_xml, const D2D1_PROPERTY_BINDING *bindings,
        UINT32 binding_count, PD2D1_EFFECT_FACTORY effect_factory)
{
    FIXME("iface %p, effect_id %s, property_xml %s, bindings %p, binding_count %u, effect_factory %p stub!\n",
            iface, debugstr_guid(effect_id), debugstr_w(property_xml), bindings, binding_count, effect_factory);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_UnregisterEffect(ID2D1Factory1 *iface, REFCLSID effect_id)
{
    FIXME("iface %p, effect_id %s stub!\n", iface, debugstr_guid(effect_id));

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_GetRegisteredEffects(ID2D1Factory1 *iface,
        CLSID *effects, UINT32 effect_count, UINT32 *returned, UINT32 *registered)
{
    FIXME("iface %p, effects %p, effect_count %u, returned %p, registered %p stub!\n",
            iface, effects, effect_count, returned, registered);

    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE d2d_factory_GetEffectProperties(ID2D1Factory1 *iface,
        REFCLSID effect_id, ID2D1Properties **props)
{
    FIXME("iface %p, effect_id %s, props %p stub!\n", iface, debugstr_guid(effect_id), props);

    return E_NOTIMPL;
}

static const struct ID2D1Factory1Vtbl d2d_factory_vtbl =
{
    d2d_factory_QueryInterface,
    d2d_factory_AddRef,
    d2d_factory_Release,
    d2d_factory_ReloadSystemMetrics,
    d2d_factory_GetDesktopDpi,
    d2d_factory_CreateRectangleGeometry,
    d2d_factory_CreateRoundedRectangleGeometry,
    d2d_factory_CreateEllipseGeometry,
    d2d_factory_CreateGeometryGroup,
    d2d_factory_CreateTransformedGeometry,
    d2d_factory_CreatePathGeometry,
    d2d_factory_CreateStrokeStyle,
    d2d_factory_CreateDrawingStateBlock,
    d2d_factory_CreateWicBitmapRenderTarget,
    d2d_factory_CreateHwndRenderTarget,
    d2d_factory_CreateDxgiSurfaceRenderTarget,
    d2d_factory_CreateDCRenderTarget,
    d2d_factory_CreateDevice,
    d2d_factory_CreateStrokeStyle1,
    d2d_factory_CreatePathGeometry1,
    d2d_factory_CreateDrawingStateBlock1,
    d2d_factory_CreateGdiMetafile,
    d2d_factory_RegisterEffectFromStream,
    d2d_factory_RegisterEffectFromString,
    d2d_factory_UnregisterEffect,
    d2d_factory_GetRegisteredEffects,
    d2d_factory_GetEffectProperties,
};

static void d2d_factory_init(struct d2d_factory *factory, D2D1_FACTORY_TYPE factory_type,
        const D2D1_FACTORY_OPTIONS *factory_options)
{
    if (factory_type != D2D1_FACTORY_TYPE_SINGLE_THREADED)
        FIXME("Ignoring factory type %#x.\n", factory_type);
    if (factory_options && factory_options->debugLevel != D2D1_DEBUG_LEVEL_NONE)
        WARN("Ignoring debug level %#x.\n", factory_options->debugLevel);

    factory->ID2D1Factory1_iface.lpVtbl = &d2d_factory_vtbl;
    factory->refcount = 1;
    d2d_factory_reload_sysmetrics(factory);
}

HRESULT WINAPI D2D1CreateFactory(D2D1_FACTORY_TYPE factory_type, REFIID iid,
        const D2D1_FACTORY_OPTIONS *factory_options, void **factory)
{
    struct d2d_factory *object;
    HRESULT hr;

    TRACE("factory_type %#x, iid %s, factory_options %p, factory %p.\n",
            factory_type, debugstr_guid(iid), factory_options, factory);

    if (!(object = heap_alloc_zero(sizeof(*object))))
        return E_OUTOFMEMORY;

    d2d_factory_init(object, factory_type, factory_options);

    TRACE("Created factory %p.\n", object);

    hr = ID2D1Factory1_QueryInterface(&object->ID2D1Factory1_iface, iid, factory);
    ID2D1Factory1_Release(&object->ID2D1Factory1_iface);

    return hr;
}

void WINAPI D2D1MakeRotateMatrix(float angle, D2D1_POINT_2F center, D2D1_MATRIX_3X2_F *matrix)
{
    float theta, sin_theta, cos_theta;

    TRACE("angle %.8e, center {%.8e, %.8e}, matrix %p.\n", angle, center.x, center.y, matrix);

    theta = angle * (M_PI / 180.0f);
    sin_theta = sinf(theta);
    cos_theta = cosf(theta);

    /* translate(center) * rotate(theta) * translate(-center) */
    matrix->_11 = cos_theta;
    matrix->_12 = sin_theta;
    matrix->_21 = -sin_theta;
    matrix->_22 = cos_theta;
    matrix->_31 = center.x - center.x * cos_theta + center.y * sin_theta;
    matrix->_32 = center.y - center.x * sin_theta - center.y * cos_theta;
}

static BOOL get_config_key_dword(HKEY default_key, HKEY application_key, const char *name, DWORD *value)
{
    DWORD type, data, size;

    size = sizeof(data);
    if (application_key && !RegQueryValueExA(application_key,
            name, 0, &type, (BYTE *)&data, &size) && type == REG_DWORD)
        goto success;

    size = sizeof(data);
    if (default_key && !RegQueryValueExA(default_key,
            name, 0, &type, (BYTE *)&data, &size) && type == REG_DWORD)
        goto success;

    return FALSE;

success:
    *value = data;
    return TRUE;
}

static void d2d_settings_init(void)
{
    HKEY default_key, tmp_key, application_key = NULL;
    char buffer[MAX_PATH + 10];
    DWORD len;

    if (RegOpenKeyA(HKEY_CURRENT_USER, "Software\\Wine\\Direct2D", &default_key))
        default_key = NULL;

    len = GetModuleFileNameA(0, buffer, MAX_PATH);
    if (len && len < MAX_PATH)
    {
        char *p, *appname = buffer;

        if ((p = strrchr(appname, '/')))
            appname = p + 1;
        if ((p = strrchr(appname, '\\')))
            appname = p + 1;
        strcat(appname, "\\Direct2D");

        if (!RegOpenKeyA(HKEY_CURRENT_USER, "Software\\Wine\\AppDefaults", &tmp_key))
        {
            if (RegOpenKeyA(tmp_key, appname, &application_key))
                application_key = NULL;
            RegCloseKey(tmp_key);
        }
    }

    if (!default_key && !application_key)
        return;

    if (get_config_key_dword(default_key, application_key, "max_version_factory", &d2d_settings.max_version_factory))
        ERR_(winediag)("Limiting maximum Direct2D factory version to %#x.\n", d2d_settings.max_version_factory);

    if (application_key)
        RegCloseKey(application_key);
    if (default_key)
        RegCloseKey(default_key);
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, void *reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
        d2d_settings_init();
    return TRUE;
}
