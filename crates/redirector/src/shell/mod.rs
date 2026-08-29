pub mod badge;
pub mod folders;
pub mod identity;

pub fn init_hooks() {
    folders::init_hooks();
    identity::init_hooks();
    badge::init_hooks();
}
