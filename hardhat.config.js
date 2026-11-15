require("@nomicfoundation/hardhat-toolbox");
const { subtask } = require("hardhat/config");
const { TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD } = require("hardhat/builtin-tasks/task-names");

// Normally Hardhat downloads the Solidity compiler from binaries.soliditylang.org.
// If you are somewhere that host is blocked, run with USE_SOLCJS=1 and Hardhat will
// use the pure-JavaScript compiler from the `solc` npm package instead.
// On a normal laptop you do NOT need this; just run `npx hardhat test`.
if (process.env.USE_SOLCJS) {
  subtask(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD, async (args, hre, runSuper) => {
    if (args.solcVersion === "0.8.24") {
      return {
        compilerPath: require.resolve("solc/soljson.js"),
        isSolcJs: true,
        version: "0.8.24",
        longVersion: require("solc").version(),
      };
    }
    return runSuper();
  });
}

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
};
