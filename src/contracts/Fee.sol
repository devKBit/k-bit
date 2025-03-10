// SPDX-License-Identifier: BUSL-1.1
// Compatible with OpenZeppelin Contracts ^5.0.0
pragma solidity 0.8.26;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

using SafeERC20 for IERC20;

contract Fee is Initializable, PausableUpgradeable, OwnableUpgradeable, UUPSUpgradeable, ReentrancyGuardUpgradeable {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address initialOwner) public initializer {
        require(initialOwner != address(0), "zero address");
        __Pausable_init();
        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();
    }

    function pause() public onlyOwner {
        _pause();
    }

    function unpause() public onlyOwner {
        _unpause();
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    using ECDSA for bytes32;

    IERC20 public usdt;
    address public perpDex;

    mapping(address => uint256) public protocolFeePercent; // ex. 15% (15000) for referrer+referee, 85% (85000) for protocol
    mapping(address => uint256) public referrerFeePercent; // ex. 90% (90000) for referrer, 10% (10000) for referee
    mapping(address => address) public referral; // referee to referrer
    mapping(address => uint256) public feeBalanceAsReferrer;
    mapping(address => uint256) public feeBalanceAsReferee;
    mapping(address => uint256) public claimedFeeBalanceAsReferrer;
    mapping(address => uint256) public claimedFeeBalanceAsReferee;


    mapping(address => uint256) public traderNonce;
    mapping(address => uint256) public refereeCount;

    address public admin;
    address public protocolFeeCollector;
    uint256 public protocolFeeBalance;


    event FeePaid(
        address indexed referee, address indexed referrer, uint256 fee, uint256 protocolFee, uint256 referrerFee, uint256 refereeFee
    );
    event ReferralFeeClaimed(address indexed trader, uint256 indexed feeToClaimAsReferrer, uint256 indexed feeToClaimAsReferee);
    event ProtocolFeeClaimed(address indexed owner, uint256 indexed protocolFee); // Maybe better to hide this?
    event ReferralRegistered(address indexed referrer, address indexed referee);
    event FeePercentSet(address indexed referrer, uint256 indexed protocolFeePercent, uint256 indexed referrerFeePercent);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can call this function");
        _;
    }

    function setPerpDexAddr(address perp) external onlyOwner {
        require(perp != address(0), "zero address");
        perpDex = perp;
    }

    function setUsdtAddr(address _usdt) external onlyOwner {
        require(IERC20Metadata(_usdt).decimals() == 6, "Decimal is not 6");
        usdt = IERC20(_usdt);
    }

    function setAdmin(address _addr) external onlyOwner {
        require(_addr != address(0), "zero address");
        admin = _addr;
    }

    function setProtocolFeeCollector(address _addr) external onlyOwner {
        require(_addr != address(0), "zero address");
        protocolFeeCollector = _addr;
    }

    function getTotalFeePercent() public pure returns (uint256) {
        return 70; // 0.07%
    }

    function getMarginFeePercent() public pure returns (uint256) {
        return 100; // 0.1%
    }

    function getFeeDenominator() public pure returns (uint256) {
        return 100_000; // can express up to 0.001%
    }

    function payFee(address referee, uint256 fee) external nonReentrant {
        require(msg.sender == perpDex, "Only perpDex can call this function");
        usdt.safeTransferFrom(perpDex, address(this), fee);
        address referrer = referral[referee];

        if (protocolFeePercent[referrer] == 0 || referrer == address(0)) {
            // No referral
            protocolFeeBalance += fee;
            emit FeePaid(referee, referrer, fee, fee, 0, 0);
            return;
        }

        uint256 protocolFee = fee * protocolFeePercent[referrer] / getFeeDenominator();
        protocolFeeBalance += protocolFee;

        uint256 feeForReferrerAndReferee = fee - protocolFee;
        uint256 referrerFee = feeForReferrerAndReferee * referrerFeePercent[referrer] / getFeeDenominator();
        feeBalanceAsReferrer[referrer] += referrerFee;

        uint256 refereeFee = feeForReferrerAndReferee - referrerFee; // fee dust goes to referee
        feeBalanceAsReferee[referee] += refereeFee;

        emit FeePaid(referee, referrer, fee, protocolFee, referrerFee, refereeFee);
    }

    function registerReferrer(address referrer, address referee, bytes calldata userSignedData) external onlyAdmin {
        require(referrer != address(0), "zero address");
        require(referee != address(0), "zero address");
        require(referrer != referee, "Cannot refer yourself");
        require(protocolFeePercent[referrer] > 0, "protocolFeePercent is 0");
        require(referral[referee] == address(0), "Referrer already exists");

        string memory message = string(
            abi.encodePacked(
                "Register referrer. Nonce: ",
                Strings.toString(traderNonce[referee]),
                ", Chain: ",
                Strings.toString(block.chainid),
                ", Contract: ",
                Strings.toHexString(address(this))
            )
        );
        traderNonce[referee]++;
        checkUser(message, bytes(message).length, userSignedData, referee);

        referral[referee] = referrer;
        refereeCount[referrer] += 1;

        emit ReferralRegistered(referrer, referee);
    }

    function claimProtocolFee() external nonReentrant {
        require(msg.sender == protocolFeeCollector, "Only collector can call this function");

        uint256 claimedFee = protocolFeeBalance;
        usdt.safeTransfer(protocolFeeCollector, claimedFee);
        protocolFeeBalance = 0;

        emit ProtocolFeeClaimed(protocolFeeCollector, claimedFee);
    }

    function claimFee() external nonReentrant {
        uint256 feeToClaimAsReferrer = feeBalanceAsReferrer[msg.sender];
        usdt.safeTransfer(msg.sender, feeToClaimAsReferrer);
        claimedFeeBalanceAsReferrer[msg.sender] += feeToClaimAsReferrer;
        feeBalanceAsReferrer[msg.sender] = 0;

        uint256 feeToClaimAsReferee = feeBalanceAsReferee[msg.sender];
        usdt.safeTransfer(msg.sender, feeToClaimAsReferee);
        claimedFeeBalanceAsReferee[msg.sender] += feeToClaimAsReferee;
        feeBalanceAsReferee[msg.sender] = 0;

        emit ReferralFeeClaimed(msg.sender, feeToClaimAsReferrer, feeToClaimAsReferee);
    }

    function setFeePercent(address referrer, uint256 _protocolFeePercent, uint256 _referrerFeePercent, bytes calldata userSignedData)
        external
        onlyAdmin
    {
        require(referrer != address(0), "zero address");
        require(_protocolFeePercent > 0, "protocolFeePercent is 0");
        require(
            _protocolFeePercent <= getFeeDenominator() && _referrerFeePercent <= getFeeDenominator(),
            "Fee percent must be less than denominator"
        );

        string memory message = string(
            abi.encodePacked(
                "Create referral code. Nonce: ",
                Strings.toString(traderNonce[referrer]),
                ", Chain: ",
                Strings.toString(block.chainid),
                ", Contract: ",
                Strings.toHexString(address(this))
            )
        );
        traderNonce[referrer]++;
        checkUser(message, bytes(message).length, userSignedData, referrer);
        protocolFeePercent[referrer] = _protocolFeePercent;
        referrerFeePercent[referrer] = _referrerFeePercent;

        emit FeePercentSet(referrer, _protocolFeePercent, _referrerFeePercent);
    }

    function checkUser(string memory message, uint256 length, bytes calldata signedData, address user) internal pure {
        bytes32 ethHashedMessage = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(length), message));
        address recoveredAddress = ethHashedMessage.recover(signedData);
        if (recoveredAddress != user) {
            bytes32 klayHashedMessage = keccak256(abi.encodePacked("\x19Klaytn Signed Message:\n", Strings.toString(length), message));
            recoveredAddress = klayHashedMessage.recover(signedData);
            require(recoveredAddress == user, "Invalid signed data");
        }
        require(recoveredAddress != address(0), "ECDSA: invalid signature");
    }

    struct ReferralInfo {
        uint256 totalFeePercent;
        uint256 protocolFeePercent;
        uint256 referrerFeePercent;
        uint256 feeBalanceAsReferrer;
        uint256 feeBalanceAsReferee;
        uint256 claimedFeeBalanceAsReferrer;
        uint256 claimedFeeBalanceAsReferee;
        uint256 refereeCount;
    }

    function getReferralInfo(address addr) external view returns (ReferralInfo memory) {
        ReferralInfo memory info = ReferralInfo({
            totalFeePercent: getTotalFeePercent(),
            protocolFeePercent: protocolFeePercent[addr],
            referrerFeePercent: referrerFeePercent[addr],
            feeBalanceAsReferrer: feeBalanceAsReferrer[addr],
            feeBalanceAsReferee: feeBalanceAsReferee[addr],
            claimedFeeBalanceAsReferrer: claimedFeeBalanceAsReferrer[addr],
            claimedFeeBalanceAsReferee: claimedFeeBalanceAsReferee[addr],
            refereeCount: refereeCount[addr]
        });
        return info;
    }
}
