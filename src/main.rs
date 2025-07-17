use frost_secp256k1_tr::{
    keys::dkg::{part1, part2, part3},
    keys::{KeyPackage, PublicKeyPackage},
    round1::{SigningCommitments, SigningNonces},
    round2::{sign, SignatureShare},
    aggregate, Identifier, Signature,
};
use rand::thread_rng;
use std::collections::BTreeMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configuration
    let threshold = 2;
    let max_signers = 3;
    let message = b"Hello, FROST!";

    // Initialize parties with more robust identifiers
    let mut parties = vec![];
    for i in 1..=max_signers {
        // Use a 16-byte array for identifier to ensure validity
        let mut id_bytes = [0u8; 16];
        id_bytes[0] = i as u8; // Unique per party
        let identifier = Identifier::derive(&id_bytes)?;
        println!("Party {} identifier: {:?}", i, identifier);
        parties.push(Party {
            identifier,
            round1_secret: None,
            round1_package: None,
            round2_secret: None,
            round2_packages: BTreeMap::new(),
            key_package: None,
            public_key_package: None,
        });
    }

    // Step 1: DKG Round 1
    let mut round1_packages = BTreeMap::new();
    for party in parties.iter_mut() {
        let mut rng = thread_rng();
        let (round1_secret, round1_package) = part1(party.identifier, max_signers as u16, threshold as u16, &mut rng)?;
        party.round1_secret = Some(round1_secret);
        party.round1_package = Some(round1_package.clone());
        round1_packages.insert(party.identifier, round1_package);
        println!("Party {:?} generated round1 package", party.identifier);
    }
    println!("Round1 packages count: {}", round1_packages.len());

    // Step 2: DKG Round 2
    for party in parties.iter_mut() {
        let round1_secret = party.round1_secret.take().ok_or("Missing round1 secret")?;
        let mut filtered_round1_packages = round1_packages.clone();
        filtered_round1_packages.remove(&party.identifier);
        println!(
            "Party {:?} filtered round1 packages: {} identifiers: {:?}",
            party.identifier,
            filtered_round1_packages.len(),
            filtered_round1_packages.keys().collect::<Vec<_>>()
        );
        if filtered_round1_packages.len() != (max_signers - 1) as usize {
            return Err(format!(
                "Party {:?} expected {} round1 packages, got {}",
                party.identifier,
                max_signers - 1,
                filtered_round1_packages.len()
            )
            .into());
        }
        let (round2_secret, round2_packages) = part2(round1_secret, &filtered_round1_packages)?;
        party.round2_secret = Some(round2_secret);
        party.round2_packages = round2_packages;
        println!("Party {:?} generated round2 packages for {} recipients", party.identifier, party.round2_packages.len());
    }

    // Collect Round 2 packages for each party
    let mut all_round2_packages = BTreeMap::new();
    for party in parties.iter() {
        for (recipient_id, package) in &party.round2_packages {
            all_round2_packages
                .entry(*recipient_id)
                .or_insert_with(BTreeMap::new)
                .insert(party.identifier, package.clone());
        }
    }
    for (recipient_id, packages) in &all_round2_packages {
        println!(
            "Recipient {:?} received round2 packages from {} senders: {:?}",
            recipient_id,
            packages.len(),
            packages.keys().collect::<Vec<_>>()
        );
        if packages.len() != (max_signers - 1) as usize {
            return Err(format!(
                "Recipient {:?} expected {} round2 packages, got {}",
                recipient_id,
                max_signers - 1,
                packages.len()
            )
            .into());
        }
    }

    // Step 3: DKG Round 3
    for party in parties.iter_mut() {
        let round2_secret = party.round2_secret.take().ok_or("Missing round2 secret")?;
        let received_round2_packages = all_round2_packages
            .get(&party.identifier)
            .ok_or("Missing round2 packages")?;
        let mut filtered_round1_packages = round1_packages.clone();
        filtered_round1_packages.remove(&party.identifier);
        let (key_package, public_key_package) = part3(
            &round2_secret,
            &filtered_round1_packages,
            received_round2_packages,
        )?;
        party.key_package = Some(key_package);
        party.public_key_package = Some(public_key_package);
        println!("Party {:?} completed DKG with key package", party.identifier);
    }

    // Step 4: Signing - Generate nonces and commitments for only the signing parties
    let mut signing_commitments = BTreeMap::new();
    let mut signing_nonces = BTreeMap::new();
    for party in parties.iter_mut().take(threshold) { // Only the first 2 parties
        let key_package = party.key_package.as_ref().ok_or("Missing key package")?;
        let mut rng = thread_rng();
        let (nonce, commitment) = frost_secp256k1_tr::round1::commit(key_package.signing_share(), &mut rng);
        signing_nonces.insert(party.identifier, nonce);
        signing_commitments.insert(party.identifier, commitment);
        println!("Party {:?} generated signing commitment", party.identifier);
    }

    // Step 5: Create Signing Package
    let signing_package = frost_secp256k1_tr::SigningPackage::new(signing_commitments, message);
    println!("Created signing package for message: {:?}", message);

    // Step 6: Generate Signature Shares (select 2 out of 3 parties for threshold)
    let mut signature_shares = BTreeMap::new();
    for party in parties.iter().take(threshold) {
        let key_package = party.key_package.as_ref().ok_or("Missing key package")?;
        let nonce = signing_nonces
            .get(&party.identifier)
            .ok_or("Missing nonce")?;
        let signature_share = sign(&signing_package, nonce, key_package)?;
        signature_shares.insert(party.identifier, signature_share);
        println!("Party {:?} generated signature share", party.identifier);
    }

    // Step 7: Aggregate Signature
    let public_key_package = parties[0]
        .public_key_package
        .as_ref()
        .ok_or("Missing public key package")?;
    let signature = aggregate(&signing_package, &signature_shares, public_key_package)?;
    println!("signature: {:?}", signature);
    println!("Aggregated signature generated");

    println!("public key {:?}", public_key_package);

    // // Step 8: Verify Signature
    // let is_valid = signature.verify(&public_key_package.verifying_key(), message);
    // println!("Signature valid: {}", is_valid);

    // if is_valid {
    //     println!("Successfully generated and verified 2/3 FROST signature for message: {:?}", message);
    // } else {
    //     println!("Signature verification failed!");
    // }

    Ok(())
}

#[derive(Clone)]
struct Party {
    identifier: Identifier,
    round1_secret: Option<frost_secp256k1_tr::keys::dkg::round1::SecretPackage>,
    round1_package: Option<frost_secp256k1_tr::keys::dkg::round1::Package>,
    round2_secret: Option<frost_secp256k1_tr::keys::dkg::round2::SecretPackage>,
    round2_packages: BTreeMap<Identifier, frost_secp256k1_tr::keys::dkg::round2::Package>,
    key_package: Option<KeyPackage>,
    public_key_package: Option<PublicKeyPackage>,
}