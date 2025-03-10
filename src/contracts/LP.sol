// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC4626Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

using SafeERC20 for IERC20;

contract LP is Initializable, ERC4626Upgradeable, PausableUpgradeable, OwnableUpgradeable, UUPSUpgradeable, ReentrancyGuardUpgradeable {
    address public perpDex;
    IERC20 public usdt;

    constructor() {
        _disableInitializers();
    }

    function initialize(address initialOwner, address usdtAddr, address perpDexAddr) public initializer {
        require(initialOwner != address(0), "zero address");
        require(usdtAddr != address(0), "zero address");
        require(perpDexAddr != address(0), "zero address");

        usdt = IERC20(usdtAddr);
        perpDex = perpDexAddr;
        __ERC20_init("K-BIT LP Token", "KLP");
        __ERC4626_init(usdt);
        __Pausable_init();
        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    function giveProfit(address trader, uint256 amount) external {
        require(msg.sender == perpDex, "Only perpDex contract can give profit");
        usdt.safeTransfer(trader, amount);
    }
}
