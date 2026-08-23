pub mod folders;
pub mod taskbar;

pub fn init_hooks() {
    folders::init_hooks();
    taskbar::init_hooks();
}
