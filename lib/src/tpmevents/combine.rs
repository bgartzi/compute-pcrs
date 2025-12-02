// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT
/*
 * We're receiving two event vectors that we don't know which PCR they
 * belong to.
 *
 * We need to combine events from vec "A" and "B" based on event groups.
 *
 * Let's say that vec A and B contain event ID "e1". e1 belongs to
 * groups g1 and g2.
 *   If the value of e1 doesn't change from A to B, it doesn't matter.
 *   If the value of e1 is different in A and B, then combinations must
 *   respect groups.
 *   That is, if e1 from A is chosen, all events "ei" that are from groups
 *   g1 or g2 must be chosen from A.
 *   Same applies for B.
 *   And all combinations must be calculated.
 *
 * Note that this kind of looks like an event tree at this point.
 * Each existing branch will be a possible solution to the problem.
 *
 * TODO:
 * - PROBLEM:
 *   Imagine that event "Ej" is the product of artifacts a1 and a2.
 *   The event tracking a1 belongs to g1 and a2 to g2.
 *   Ej belongs to g1 and g2.
 *   Choose g1 from event vec A and g2 from event vec B.
 *   How can you compute Ej? There's a conflict.
 *     If g1 and g2 are from A, then Ej is from A.
 *     If g1 and g2 are from B, then Ej is from B.
 *     If g1 is from A and g2 from B, Ej needs to be recomputed.
 *   PROBLEM
 *   Analysis:
 *     Only PCR7 contains multigroup events.
 *     They are combinations of sb variables, bootloader, and mokvars.
 *     It would require upgrading the bootloader while updating secureboot
 *     variables to hit this issue.
 *     Could it be possible, in that case, that a weird mix happens?
 *
 *  Solutions:
 *    - Raise an error that the operator knows. Enter into "recovery".
 *      - Operator asks for the events that need to be recomputed.
 *        - If each event could be computed separately, this would be easier.
 *        - If each event computation fn would take the same arguments as
 *          the rest, it would make it way more easier.
 *    - We could just insert some information about missing events in the tree.
 *      - For example: image_A groups mask + image_B groups mask + value =
 *        "MISSINGEVENTDUETOCONFLICT" or something like that.
 *      - We could even wrap the solution into a struct containing a vector of
 *        missing pieces, e.g. a vector of tuples containing
 *        [(solution_0, missing_event_0),(solution_1, missing_event_1),...,(solution_N, missing_event_N)]
 *        together with the vector of tpmevent vectors.
 *      - Operator would then need to check possible solutions,
 *        look for missing pieces and if there are, mount the images and take
 *        needed actions.
 *      - This would need another library interface such as
 *        compute_event(event_id: TPMEventID, path_A: &str, path_B: &str) -> TPMEvent
 *
 *
 *
 *
 * That means that if vec A and B contain event "i", and
 * We would split the whole problem into sub-problems per PCR number.
 * However, groups being applied can be cross-PCR. In other words, there are some event groups
 * First,
 *  - We need to know which PCRs we are dealing with.
*/
use std::collections::HashMap;

use itertools::Itertools;

use super::*;
use crate::pcrs::{Pcr, compile_pcrs};

#[cfg(test)]
mod tests;

// pub fn combine_images(images: &Vec<Vec<TPMEvent>>) -> Vec<Vec<Pcr>> {
//     images
//         .iter()
//         .combinations(2)
//         .flat_map(|p| combine(p[0], p[1]))
//         .unique()
//         .collect()
// }

pub fn combine(images: &Vec<Vec<TPMEvent>>) -> Vec<Vec<Pcr>> {
    let event_maps = images.iter().map(|i| tpm_event_id_hashmap(i)).collect();
    let groups = vec![0; images.len()];

    let event = TPMEventID::PcrRootNodeEvent.next().unwrap();
    match event_subtree(&event, &event_maps, groups) {
        Some(st) => st
            .iter()
            .flat_map(|t| t.branches())
            .map(|e| compile_pcrs(&e))
            .unique()
            .collect(),
        None => vec![],
    }
}

/// For recovery, we would need some information such as
///     - pcr number
///     - images involved in the conflict
///         * Is everyone part of the conflict?
///     - 
fn event_subtree(
    event_id: &TPMEventID,
    event_maps: &Vec<HashMap<TPMEventID, TPMEvent>>,
    groups: Vec<u32>,
) -> Option<Vec<tree::EventNode<TPMEvent>>> {
    let event_groups = event_id.groups();
    let opts: Vec<_> = event_maps.iter().map(|m| m.get(event_id)).collect();
    // Divergences represent reasons why the tree might diverge
    let mut divs: Vec<(&TPMEvent, Vec<u32>)> = vec![];
    let mut nodes: Vec<tree::EventNode<TPMEvent>> = vec![];
    let mut event_required = true;
    // Relates TPMEvents and their global index and div index
    let mut events_added: HashMap<TPMEvent, (Vec<usize>, usize)> = HashMap::new();
    let mut conflicts: Vec<usize> = vec![];

    println!("-----------------------------------------------------------------");
    println!("PCR Event {event_id:?}");
    println!("Groups needed:   {:#034b}", event_groups);
    for (j, g) in groups.iter().enumerate() {
        println!("Group {j} has:     {:#034b}", g);
    }
    println!("");

    for (i, opt) in opts.iter().enumerate() {
        match opt {
            Some(event) => {
                // FIXME: Should we check if the missing groups we need to lock
                //        aren't locked by anyone else?
                if can_own(i, &groups, event_groups) {
                    let (global_ids, div_idx) = events_added
                        .entry((*event).clone())
                        .or_insert_with(|| (vec![], divs.len()));

                    global_ids.push(i);
                    if divs.len() == *div_idx {
                        divs.push((&event, groups.clone()));
                    }

                    let mut masked_groups = divs[*div_idx].1.clone();
                    masked_groups[i] |= event_groups;
                    divs[*div_idx].1 = masked_groups;
                    println!("Pushing image {i}, total divs: {}", divs.len());
                    println!("Groups masked:   {:#034b}", divs[*div_idx].1[i]);
                //} else if !other_owns_fully(i, &groups, event_groups) {
                } else if other_owns_partially(i, &groups, event_groups) && !other_owns_fully(i, &groups, event_groups) {
                    // conflict pairs.
                    // We need to know i
                    // and who is locking those groups that we are missing
                    //
                    // NOTE: Is it different when
                    //  - Others partially own a group
                    //      - This means we're facing a conflict
                    //  - Others completely own a group
                    //      - I think this would mean we're filling another
                    //        branch that we don't care about.
                    println!("Considering conflict");
                    println!("\tImage {i}");
                    println!("\tFully owned? {}", fully_owned(groups[i], event_groups));
                    println!("\tPartly owned? {}", other_owns_partially(i, &groups, event_groups));
                    conflicts.push(i)
                }
            }
            None => event_required = false,
        }
    }

    if events_added.len() == 1 && event_required {
        divs = events_added
            .iter()
            .map(|(e, _)| (e, groups.clone()))
            .collect()
    }

    //if !conflicts.is_empty() && divs.is_empty() {
    if !conflicts.is_empty() {
        panic!("NEW EVENT GROUP DETECTION ALG");
    }

    if divs.is_empty() {
        // Event is required but wasn't pushed to divergences...
        // Means we met an event id/tree branching group conflict
        if event_required {
            // NOTE: (remove) It's impossible that conflicts.is_empty() now
            // TODO: switch from panic to result?
            println!("N divs: {}" ,divs.len());
            println!("Conflicts: {:?}", conflicts);
            panic!("Event group conflict hit");
        }
        println!("\n\n");
        return event_subtree(&event_id.next()?, event_maps, groups);
    }

    for (event, group_masks) in divs {
        let mut node = tree::EventNode::<TPMEvent>::new(event.clone());
        if let Some(children) = event_subtree(&event_id.next()?, &event_maps, group_masks.clone()) {
            for c in children {
                node.add_child(c);
            }
        }
        nodes.push(node);
    }

    println!("pushed {} nodes", nodes.len());
    println!("\n\n");

    Some(nodes)
}

fn tpm_event_id_hashmap(events: &[TPMEvent]) -> HashMap<TPMEventID, TPMEvent> {
    events.iter().map(|e| (e.id.clone(), e.clone())).collect()
}

fn group_masks_overlap(groups: &[u32]) -> bool {
    let mut sum: u32 = 0;

    for group in groups.iter() {
        if sum & group != 0 {
            return true;
        }
        sum |= group;
    }

    false
}

// Checks if any of the other images owns any required group previously
fn other_owns_partially(owner_index: usize, owned_groups: &Vec<u32>, event_groups: u32) -> bool {
    owned_groups
        .iter()
        .enumerate()
        .filter(|(i, e)| *i != owner_index && partially_owned(**e, event_groups))
        .count()
        != 0
}

fn partially_owned(owner: u32, groups: u32) -> bool {
    groups & owner != 0
}

fn fully_owned(owner: u32, groups: u32) -> bool {
    (owner & groups) == groups
}

fn other_owns_fully(owner_index: usize, owned_groups: &Vec<u32>, event_groups: u32) -> bool {
    owned_groups
        .iter()
        .enumerate()
        .filter(|(i, e)| *i != owner_index && fully_owned(**e, event_groups))
        .count()
        != 0
}

fn can_own(owner_index: usize, owned_groups: &Vec<u32>, event_groups: u32) -> bool {
    let missing_groups = !owned_groups[owner_index] & event_groups;
    !other_owns_partially(owner_index, owned_groups, missing_groups)
}
