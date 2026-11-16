use lockset_core::{Change, Plan};

pub fn plan(plan: &Plan, dry_run: bool) {
    for note in &plan.notes {
        println!("{note}");
    }
    for warning in &plan.warnings {
        println!("warning: {warning}");
    }
    if dry_run {
        if plan.changes.is_empty() {
            println!("nothing to do");
        }
        for item in &plan.changes {
            println!("would {}", describe(item));
        }
    }
}

pub fn describe(item: &Change) -> String {
    match item {
        Change::WriteFile { path, .. } => format!("write {path}"),
        Change::UpdateKeys { payload } => format!("re-wrap {payload}"),
        Change::RotateDataKey { payload } => format!("rotate the data key of {payload}"),
        Change::SetValue {
            payload,
            name,
            value: _,
        } => format!("set {name} in {payload}"),
        Change::StoreKey { custody } => format!("store the key in {custody}"),
        Change::ForgetKey { custody } => format!("remove the key from {custody}"),
    }
}
