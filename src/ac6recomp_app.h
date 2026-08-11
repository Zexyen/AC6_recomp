#pragma once

#include <memory>

#include <rex/rex_app.h>

#include "ac6_native_graphics_overlay.h"
#include "generated/ac6recomp_config.h"

class Ac6recompApp : public rex::ReXApp {
 public:
  using rex::ReXApp::ReXApp;

  static std::unique_ptr<rex::ui::WindowedApp> Create(
      rex::ui::WindowedAppContext& ctx) {
    return std::unique_ptr<Ac6recompApp>(new Ac6recompApp(ctx, "ac6recomp", PPCImageConfig));
  }

 protected:
  void OnPreSetup(rex::RuntimeConfig& config) override {
    rex::ReXApp::OnPreSetup(config);
    config.expected_xex_sha256 =
        "6eefba42cdfe9121207e534d8d290009c98b1a8c60ae5334a33a4f15167cbbbc";
  }

  void OnCreateDialogs(rex::ui::ImGuiDrawer* drawer) override {
    rex::ReXApp::OnCreateDialogs(drawer);
    native_graphics_status_dialog_ =
        std::make_unique<ac6::graphics::NativeGraphicsStatusDialog>(drawer);
    native_graphics_status_dialog_->Show();
  }

 private:
  std::unique_ptr<ac6::graphics::NativeGraphicsStatusDialog> native_graphics_status_dialog_;
};
