const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("Pxp201Registry", function () {
  it("publish -> getRecord -> revoke", async function () {
    const [publisher, other] = await ethers.getSigners();

    const Factory = await ethers.getContractFactory("Pxp201Registry");
    const reg = await Factory.deploy();
    await reg.waitForDeployment();

    const recordId = ethers.keccak256(ethers.toUtf8Bytes("demo-record-1"));
    const uri = "ipfs://bafybeigdyr...demo-ciphertext";
    const cipher = 1;

    const ciphertextHash = ethers.keccak256(ethers.toUtf8Bytes("ciphertext-bytes-demo"));
    const aadHash = ethers.keccak256(ethers.toUtf8Bytes("aad-bytes-demo"));
    const accessCommitment = ethers.keccak256(ethers.toUtf8Bytes("access-json-canonical-demo"));

    await expect(reg.connect(publisher).publish(
      recordId, uri, cipher, ciphertextHash, aadHash, accessCommitment
    ))
      .to.emit(reg, "Pxp201Published");

    const rec = await reg.getRecord(recordId);

    expect(rec.publisher).to.equal(publisher.address);
    expect(rec.uri).to.equal(uri);
    expect(rec.cipher).to.equal(cipher);
    expect(rec.ciphertextHash).to.equal(ciphertextHash);
    expect(rec.aadHash).to.equal(aadHash);
    expect(rec.accessCommitment).to.equal(accessCommitment);
    expect(rec.revoked).to.equal(false);

    // Only publisher can revoke
    await expect(reg.connect(other).revoke(recordId)).to.be.reverted;

    await expect(reg.connect(publisher).revoke(recordId))
      .to.emit(reg, "Pxp201Revoked");

    const rec2 = await reg.getRecord(recordId);
    expect(rec2.revoked).to.equal(true);
  });
});
