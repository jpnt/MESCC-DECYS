static int sae_derive_pwe_ecc(struct sae_data *sae, const u8 *addr1,
			      const u8 *addr2, const u8 *password,
			      size_t password_len)
{
	u8 counter, k = 4;
	u8 addrs[2 * ETH_ALEN];
	const u8 *addr[2];
	size_t len[2];
	int found = 0;
	struct crypto_ec_point *pwe_tmp;

	if (sae->tmp->pwe_ecc == NULL) {
		sae->tmp->pwe_ecc = crypto_ec_point_init(sae->tmp->ec);
		if (sae->tmp->pwe_ecc == NULL)
			return -1;
	}
	pwe_tmp = crypto_ec_point_init(sae->tmp->ec);
	if (pwe_tmp == NULL)
		return -1;

	wpa_hexdump_ascii_key(MSG_DEBUG, "SAE: password",
			      password, password_len);

	/*
	 * H(salt, ikm) = HMAC-SHA256(salt, ikm)
	 * pwd-seed = H(MAX(STA-A-MAC, STA-B-MAC) || MIN(STA-A-MAC, STA-B-MAC),
	 *              password || counter)
	 */
	sae_pwd_seed_key(addr1, addr2, addrs);

	addr[0] = password;
	len[0] = password_len;
	addr[1] = &counter;
	len[1] = sizeof(counter);

	/*
	 * Continue for at least k iterations to protect against side-channel
	 * attacks that attempt to determine the number of iterations required
	 * in the loop.
	 */
	for (counter = 1; counter < k || !found; counter++) {
		u8 pwd_seed[SHA256_MAC_LEN];
		int res;

		if (counter > 200) {
			/* This should not happen in practice */
			wpa_printf(MSG_DEBUG, "SAE: Failed to derive PWE");
			break;
		}

		wpa_printf(MSG_DEBUG, "SAE: counter = %u", counter);
		if (hmac_sha256_vector(addrs, sizeof(addrs), 2, addr, len,
				       pwd_seed) < 0)
			break;
		res = sae_test_pwd_seed_ecc(sae, pwd_seed,
					    found ? pwe_tmp :
					    sae->tmp->pwe_ecc);
		if (res < 0)
			break;
		if (res == 0)
			continue;
		if (found) {
			wpa_printf(MSG_DEBUG, "SAE: Ignore this PWE (one was "
				   "already selected)");
		} else {
			wpa_printf(MSG_DEBUG, "SAE: Use this PWE");
			found = 1;
		}
	}

	crypto_ec_point_deinit(pwe_tmp, 1);

	return found ? 0 : -1;
}
