// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

using SafeERC20 for IERC20;

error InvalidAdmin();
error ZeroAddress();
error InvalidPriceData();
error InvalidPositionStatus();
error InvalidProtocolClaimable();
error NextPositionIdExists();

interface ILP {
    function giveProfit(address trader, uint256 amount) external;
}

interface IFee {
    function payFee(address referee, uint256 fee) external;
    function getTotalFeePercent() external view returns (uint256);
    function getMarginFeePercent() external view returns (uint256);
    function getFeeDenominator() external view returns (uint256);
}

interface IBisonAIRouter {
    function latestRoundData(string calldata feedName) external view returns (uint64 id, int256 answer, uint256 updatedAt);
    function getRoundData(string calldata _feedName, uint64 _roundId) external view returns (uint64 id, int256 answer, uint256 updatedAt);
}

interface IBisonAISubmissionProxy {
    function submitStrict(
        bytes32[] calldata _feedHashes,
        int256[] calldata _answers,
        uint256[] calldata _timestamps,
        bytes[] calldata _proofs
    ) external;
    function submitSingleWithoutSupersedValidation(bytes32 _feedHash, int256 _answer, uint256 _timestamp, bytes calldata _proof) external;
    function submitWithoutSupersedValidation(
        bytes32[] calldata _feedHashes,
        int256[] calldata _answers,
        uint256[] calldata _timestamps,
        bytes[] calldata _proofs
    ) external;
    function lastSubmissionTimes(bytes32) external view returns (uint256);
}

interface IPyth {
    struct PythPrice {
        int64 price;
        uint64 conf;
        int32 expo;
        uint64 publishTime;
    }

    struct PythPriceFeed {
        bytes32 id;
        PythPrice price;
        PythPrice emaPrice;
    }

    function getUpdateFee(bytes[] calldata updateData) external view returns (uint256);
    function getPriceNoOlderThan(bytes32 id, uint256 age) external view returns (PythPrice memory);
    function updatePriceFeeds(bytes[] calldata updateData) external payable;
    function parsePriceFeedUpdates(bytes[] calldata updateData, bytes32[] calldata priceIds, uint64 minPublishTime, uint64 maxPublishTime)
        external
        payable
        returns (PythPriceFeed[] memory priceFeeds);
}

library PerpDexPricesLib {
    function submitAndGetLatestPrice(
        PerpDexLib.OraclePrices calldata priceData,
        PerpDexLib.TokenType tokenType,
        IBisonAISubmissionProxy bisonAISubmissionProxy,
        IBisonAIRouter bisonAIRouter,
        IPyth pyth
    ) external returns (uint256) {
        require(
            priceData.feedHashes.length == 1 && priceData.answers.length == 1 && priceData.timestamps.length == 1
                && priceData.proofs.length == 1,
            "Length is not 1"
        );

        uint256 currentPrice = 0;
        if (priceData.oracleType == PerpDexLib.OracleType.BisonAI) {
            bisonAISubmissionProxy.submitSingleWithoutSupersedValidation(
                priceData.feedHashes[0], priceData.answers[0], priceData.timestamps[0], priceData.proofs[0]
            );
            require(
                bisonAISubmissionProxy.lastSubmissionTimes(priceData.feedHashes[0]) >= priceData.timestamps[0],
                "Price is not up to date (BisonAI)"
            ); // Should not happen.
            string memory feedName = getBisonAIFeedName(tokenType);
            (, int256 answer,) = bisonAIRouter.latestRoundData(feedName);
            require(answer > 0, "Price is 0 (BisonAI)");
            currentPrice = uint256(answer);
        } else if (priceData.oracleType == PerpDexLib.OracleType.Pyth) {
            uint256 feeAmount = pyth.getUpdateFee(priceData.proofs);
            pyth.updatePriceFeeds{value: feeAmount}(priceData.proofs);
            currentPrice = getPythPrice(tokenType, pyth);
        } else {
            revert("Unknown oracle type");
        }

        require(currentPrice > 0, "Price is 0");
        return currentPrice;
    }

    function submitAndGetBisonAIRoundId(
        PerpDexLib.OraclePrices calldata priceData,
        IBisonAISubmissionProxy bisonAISubmissionProxy,
        IBisonAIRouter bisonAIRouter
    ) external {
        require(priceData.oracleType == PerpDexLib.OracleType.BisonAI, "Wrong oracle type");
        require(
            priceData.feedHashes.length == priceData.answers.length && priceData.feedHashes.length == priceData.timestamps.length
                && priceData.feedHashes.length == priceData.proofs.length,
            "Lengths are not equal"
        );

        checkPriceDataOrder(priceData);
        bisonAISubmissionProxy.submitWithoutSupersedValidation(
            priceData.feedHashes, priceData.answers, priceData.timestamps, priceData.proofs
        );

        for (uint256 i = 0; i < priceData.feedHashes.length; i++) {
            require(
                bisonAISubmissionProxy.lastSubmissionTimes(priceData.feedHashes[i]) >= priceData.timestamps[i],
                "Price is not up to date (BisonAI)"
            ); // Should not happen.
            PerpDexLib.TokenType tokenType = PerpDexLib.TokenType(i);
            string memory feedName = getBisonAIFeedName(tokenType);
            (uint64 roundId, int256 answer,) = bisonAIRouter.latestRoundData(feedName);
            require(answer > 0, "Price is 0 (BisonAI)");
            emit PerpDex.SubmittedRoundId(tokenType, roundId);
        }
    }

    function getPythPrice(PerpDexLib.TokenType tokenType, IPyth pyth) public view returns (uint256) {
        bytes32 feedHash;
        if (tokenType == PerpDexLib.TokenType.Btc) {
            feedHash = 0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43;
        } else if (tokenType == PerpDexLib.TokenType.Klay) {
            feedHash = 0x452d40e01473f95aa9930911b4392197b3551b37ac92a049e87487b654b4ebbe;
        } else if (tokenType == PerpDexLib.TokenType.Wemix) {
            feedHash = 0xf63f008474fad630207a1cfa49207d59bca2593ea64fc0a6da9bf3337485791c;
        } else if (tokenType == PerpDexLib.TokenType.Eth) {
            feedHash = 0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace;
        } else if (tokenType == PerpDexLib.TokenType.Doge) {
            feedHash = 0xdcef50dd0a4cd2dcc17e45df1676dcb336a11a61c69df7a0299b0150c672d25c;
        } else if (tokenType == PerpDexLib.TokenType.Pepe) {
            feedHash = 0xd69731a2e74ac1ce884fc3890f7ee324b6deb66147055249568869ed700882e4;
        } else if (tokenType == PerpDexLib.TokenType.Sol) {
            feedHash = 0xef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d;
        } else if (tokenType == PerpDexLib.TokenType.Xrp) {
            feedHash = 0xec5d399846a9209f3fe5881d70aae9268c94339ff9817e8d18ff19fa05eea1c8;
        } else if (tokenType == PerpDexLib.TokenType.Apt) {
            feedHash = 0x03ae4db29ed4ae33d323568895aa00337e658e348b37509f5372ae51f0af00d5;
        } else if (tokenType == PerpDexLib.TokenType.Sui) {
            feedHash = 0x23d7315113f5b1d3ba7a83604c44b94d79f4fd69af77f804fc7f920a6dc65744;
        } else if (tokenType == PerpDexLib.TokenType.Shib) {
            feedHash = 0xf0d57deca57b3da2fe63a493f4c25925fdfd8edf834b20f93e1f84dbd1504d4a;
        } else if (tokenType == PerpDexLib.TokenType.Sei) {
            feedHash = 0x53614f1cb0c031d4af66c04cb9c756234adad0e1cee85303795091499a4084eb;
        } else if (tokenType == PerpDexLib.TokenType.Ada) {
            feedHash = 0x2a01deaec9e51a579277b34b122399984d0bbf57e2458a7e42fecd2829867a0d;
        } else if (tokenType == PerpDexLib.TokenType.Pol) {
            feedHash = 0xffd11c5a1cfd42f80afb2df4d9f264c15f956d68153335374ec10722edd70472;
        } else if (tokenType == PerpDexLib.TokenType.Bnb) {
            feedHash = 0x2f95862b045670cd22bee3114c39763a4a08beeb663b145d283c31d7d1101c4f;
        } else if (tokenType == PerpDexLib.TokenType.Dot) {
            feedHash = 0xca3eed9b267293f6595901c734c7525ce8ef49adafe8284606ceb307afa2ca5b;
        } else if (tokenType == PerpDexLib.TokenType.Ltc) {
            feedHash = 0x6e3f3fa8253588df9326580180233eb791e03b443a3ba7a1d892e73874e19a54;
        } else if (tokenType == PerpDexLib.TokenType.Avax) {
            feedHash = 0x93da3352f9f1d105fdfe4971cfa80e9dd777bfc5d0f683ebb6e1294b92137bb7;
        } else if (tokenType == PerpDexLib.TokenType.Trump) {
            feedHash = 0x879551021853eec7a7dc827578e8e69da7e4fa8148339aa0d3d5296405be4b1a;
        } else {
            revert("Unknown token type");
        }

        IPyth.PythPrice memory pythPriceData = pyth.getPriceNoOlderThan(feedHash, 10);
        require(pythPriceData.price > 0, "Price is 0 (Pyth)");

        if (tokenType == PerpDexLib.TokenType.Pepe || tokenType == PerpDexLib.TokenType.Shib) {
            // PEPE, SHIB has decimal 10. Rest are 8
            return uint256(uint64(pythPriceData.price / 100));
        }

        return uint256(uint64(pythPriceData.price));
    }

    function getBisonAIFeedName(PerpDexLib.TokenType tokenType) internal pure returns (string memory) {
        if (tokenType == PerpDexLib.TokenType.Btc) {
            return "BTC-USDT";
        } else if (tokenType == PerpDexLib.TokenType.Klay) {
            return "KAIA-USDT";
        } else if (tokenType == PerpDexLib.TokenType.Wemix) {
            return "WEMIX-USDT";
        } else if (tokenType == PerpDexLib.TokenType.Eth) {
            return "ETH-USDT";
        } else if (tokenType == PerpDexLib.TokenType.Doge) {
            return "DOGE-USDT";
        } else if (tokenType == PerpDexLib.TokenType.Pepe) {
            return "PEPE-USDT";
        } else if (tokenType == PerpDexLib.TokenType.Sol) {
            return "SOL-USDT";
        } else if (tokenType == PerpDexLib.TokenType.Xrp) {
            return "XRP-USDT";
        } else if (tokenType == PerpDexLib.TokenType.Apt) {
            return "APT-USDT";
        } else if (tokenType == PerpDexLib.TokenType.Sui) {
            return "SUI-USDT";
        } else if (tokenType == PerpDexLib.TokenType.Shib) {
            return "SHIB-USDT";
        } else if (tokenType == PerpDexLib.TokenType.Sei) {
            return "SEI-USDT";
        } else if (tokenType == PerpDexLib.TokenType.Ada) {
            return "ADA-USDT";
        } else if (tokenType == PerpDexLib.TokenType.Pol) {
            return "POL-USDT";
        } else if (tokenType == PerpDexLib.TokenType.Bnb) {
            return "BNB-USDT";
        } else if (tokenType == PerpDexLib.TokenType.Dot) {
            return "DOT-USDT";
        } else if (tokenType == PerpDexLib.TokenType.Ltc) {
            return "LTC-USDT";
        } else if (tokenType == PerpDexLib.TokenType.Avax) {
            return "AVAX-USDT";
        } else if (tokenType == PerpDexLib.TokenType.Trump) {
            return "TRUMP-USDT";
        } else {
            revert("Unknown token type");
        }
    }

    function getPythFeedHashOrder() internal pure returns (bytes32[] memory) {
        bytes32[] memory feedHashes = new bytes32[](uint256(type(PerpDexLib.TokenType).max) + 1);
        feedHashes[0] = 0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43;
        feedHashes[1] = 0x452d40e01473f95aa9930911b4392197b3551b37ac92a049e87487b654b4ebbe;
        feedHashes[2] = 0xf63f008474fad630207a1cfa49207d59bca2593ea64fc0a6da9bf3337485791c;
        feedHashes[3] = 0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace;
        feedHashes[4] = 0xdcef50dd0a4cd2dcc17e45df1676dcb336a11a61c69df7a0299b0150c672d25c;
        feedHashes[5] = 0xd69731a2e74ac1ce884fc3890f7ee324b6deb66147055249568869ed700882e4;
        feedHashes[6] = 0xef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d;
        feedHashes[7] = 0xec5d399846a9209f3fe5881d70aae9268c94339ff9817e8d18ff19fa05eea1c8;
        feedHashes[8] = 0x03ae4db29ed4ae33d323568895aa00337e658e348b37509f5372ae51f0af00d5;
        feedHashes[9] = 0x23d7315113f5b1d3ba7a83604c44b94d79f4fd69af77f804fc7f920a6dc65744;
        feedHashes[10] = 0xf0d57deca57b3da2fe63a493f4c25925fdfd8edf834b20f93e1f84dbd1504d4a;
        feedHashes[11] = 0x53614f1cb0c031d4af66c04cb9c756234adad0e1cee85303795091499a4084eb;
        feedHashes[12] = 0x2a01deaec9e51a579277b34b122399984d0bbf57e2458a7e42fecd2829867a0d;
        feedHashes[13] = 0xffd11c5a1cfd42f80afb2df4d9f264c15f956d68153335374ec10722edd70472;
        feedHashes[14] = 0x2f95862b045670cd22bee3114c39763a4a08beeb663b145d283c31d7d1101c4f;
        feedHashes[15] = 0xca3eed9b267293f6595901c734c7525ce8ef49adafe8284606ceb307afa2ca5b;
        feedHashes[16] = 0x6e3f3fa8253588df9326580180233eb791e03b443a3ba7a1d892e73874e19a54;
        feedHashes[17] = 0x93da3352f9f1d105fdfe4971cfa80e9dd777bfc5d0f683ebb6e1294b92137bb7;
        feedHashes[18] = 0x879551021853eec7a7dc827578e8e69da7e4fa8148339aa0d3d5296405be4b1a;
        return feedHashes;
    }

    function checkPythPriceFeedOrder(IPyth.PythPriceFeed[] memory priceFeeds) internal pure {
        bytes32[] memory feedHashOrder = getPythFeedHashOrder();
        for (uint256 i = 0; i < priceFeeds.length; i++) {
            require(priceFeeds[i].id == feedHashOrder[i], "Feed hash is not correct");
        }
    }

    function checkPriceDataOrder(PerpDexLib.OraclePrices calldata priceData) internal pure {
        if (priceData.oracleType == PerpDexLib.OracleType.BisonAI) {
            for (uint256 i = 0; i < priceData.feedHashes.length; i++) {
                require(
                    priceData.feedHashes[i] == keccak256(abi.encodePacked(getBisonAIFeedName(PerpDexLib.TokenType(i)))),
                    "Feed hash is not correct (BisonAI)"
                );
            }
        } else if (priceData.oracleType == PerpDexLib.OracleType.Pyth) {
            bytes32[] memory feedHashOrder = getPythFeedHashOrder();
            for (uint256 i = 0; i < priceData.feedHashes.length; i++) {
                require(priceData.feedHashes[i] == feedHashOrder[i], "Feed hash is not correct (Pyth)");
            }
        } else {
            revert("Unknown oracle type");
        }
    }

    function getPreviousPriceAndTime(
        uint64[] calldata roundIds,
        PerpDexLib.OraclePrices calldata priceData,
        IBisonAIRouter bisonAIRouter,
        IPyth pyth
    ) external returns (uint256[] memory, uint256[] memory) {
        checkPriceDataOrder(priceData);
        if (priceData.oracleType == PerpDexLib.OracleType.BisonAI) {
            require(roundIds.length > 0, "RoundIds length is 0");
            uint256[] memory prices = new uint256[](roundIds.length);
            uint256[] memory times = new uint256[](roundIds.length);
            for (uint256 i = 0; i < roundIds.length; i++) {
                (, int256 answer, uint256 updatedAt) = bisonAIRouter.getRoundData(getBisonAIFeedName(PerpDexLib.TokenType(i)), roundIds[i]);
                require(answer > 0, "Price is 0 (BisonAI)");
                prices[i] = uint256(answer);
                times[i] = updatedAt;
            }
            return (prices, times);
        } else if (priceData.oracleType == PerpDexLib.OracleType.Pyth) {
            uint256 feeAmount = pyth.getUpdateFee(priceData.proofs);
            IPyth.PythPriceFeed[] memory priceFeeds = pyth.parsePriceFeedUpdates{value: feeAmount}(
                priceData.proofs, priceData.feedHashes, uint64(priceData.timestamps[0]), uint64(priceData.timestamps[0])
            );
            checkPythPriceFeedOrder(priceFeeds);

            uint256[] memory prices = new uint256[](priceData.feedHashes.length);
            uint256[] memory times = new uint256[](priceData.feedHashes.length);
            for (uint256 i = 0; i < priceFeeds.length; i++) {
                int64 price = priceFeeds[i].price.price;
                require(price > 0, "Price is 0 (Pyth)");
                if (
                    priceFeeds[i].id == 0xd69731a2e74ac1ce884fc3890f7ee324b6deb66147055249568869ed700882e4
                        || priceFeeds[i].id == 0xf0d57deca57b3da2fe63a493f4c25925fdfd8edf834b20f93e1f84dbd1504d4a
                ) {
                    price = price / 100;
                }
                require(price == priceData.answers[i], "Price is not correct (Pyth)");
                prices[i] = uint256(uint64(price));

                require(priceFeeds[i].price.publishTime == priceData.timestamps[i], "Time is not correct (Pyth)");
                times[i] = priceFeeds[i].price.publishTime;
            }
            return (prices, times);
        } else {
            revert("Unknown oracle type");
        }
    }

    function safeTransferFromAndCheckBalance(address from, address to, uint256 amount, IERC20 usdt) external {
        uint256 balanceBefore = usdt.balanceOf(to);
        usdt.safeTransferFrom(from, to, amount);
        uint256 balanceAfter = usdt.balanceOf(to);
        require(balanceAfter - balanceBefore == amount, "Transfer failed");
    }

    function safeTransferAndCheckBalance(address to, uint256 amount, IERC20 usdt) public {
        uint256 balanceBefore = usdt.balanceOf(to);
        usdt.safeTransfer(to, amount);
        uint256 balanceAfter = usdt.balanceOf(to);
        require(balanceAfter - balanceBefore == amount, "Transfer failed");
    }
}

library PerpDexAuthLib {
    using ECDSA for bytes32;

    enum AdminType {
        Liquidation,
        LimitOrder,
        SingleOpen,
        Close,
        Tpsl
    }

    function checkUser(string calldata message, uint256 length, bytes calldata signedData, address user) external pure {
        bytes32 ethHashedMessage = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(length), message));
        address recoveredAddress = ethHashedMessage.recover(signedData);
        if (recoveredAddress != user) {
            bytes32 klayHashedMessage = keccak256(abi.encodePacked("\x19Klaytn Signed Message:\n", Strings.toString(length), message));
            recoveredAddress = klayHashedMessage.recover(signedData);
            require(recoveredAddress == user, "Invalid signed data");
        }
        require(recoveredAddress != address(0), "ECDSA: invalid signature");
    }

    function getOpenLimitOrderMsg(PerpDexLib.OpenLimitOrderData calldata o, uint256 nonce, address contractAddr)
        external
        view
        returns (string memory)
    {
        string memory message = string(
            abi.encodePacked(
                "Open Limit Order for Token: ",
                Strings.toString(uint256(o.tokenType)),
                ", Margin: ",
                Strings.toString(o.marginAmount),
                ", Leverage: ",
                Strings.toString(o.leverage),
                ", Long: ",
                Strings.toString(o.long ? 1 : 0),
                ", Wanted Price: ",
                Strings.toString(o.wantedPrice),
                ", TP: ",
                Strings.toString(o.tpPrice),
                ", SL: ",
                Strings.toString(o.slPrice),
                ", Nonce: ",
                Strings.toString(nonce),
                ", Chain: ",
                Strings.toString(block.chainid),
                ", Contract: ",
                Strings.toHexString(contractAddr)
            )
        );
        return message;
    }

    function getCloseLimitOrderMsg(uint256 positionId, uint256 nonce, address contractAddr) external view returns (string memory) {
        string memory message = string(
            abi.encodePacked(
                "Close Limit Order: ",
                Strings.toString(positionId),
                ", Nonce: ",
                Strings.toString(nonce),
                ", Chain: ",
                Strings.toString(block.chainid),
                ", Contract: ",
                Strings.toHexString(contractAddr)
            )
        );
        return message;
    }

    function getOpenPositionMsg(PerpDexLib.OpenPositionData calldata o, uint256 nonce, address contractAddr)
        external
        view
        returns (string memory)
    {
        string memory message = string(
            abi.encodePacked(
                "Open position for Token: ",
                Strings.toString(uint256(o.tokenType)),
                ", Margin: ",
                Strings.toString(o.marginAmount),
                ", Leverage: ",
                Strings.toString(o.leverage),
                ", Long: ",
                Strings.toString(o.long ? 1 : 0),
                ", TP: ",
                Strings.toString(o.tpPrice),
                ", SL: ",
                Strings.toString(o.slPrice),
                ", Price: ",
                Strings.toString(o.expectedPrice),
                ", Nonce: ",
                Strings.toString(nonce),
                ", Chain: ",
                Strings.toString(block.chainid),
                ", Contract: ",
                Strings.toHexString(contractAddr)
            )
        );
        return message;
    }

    function getClosePositionMsg(uint256 positionId, uint256 nonce, address contractAddr) external view returns (string memory) {
        string memory message = string(
            abi.encodePacked(
                "Close Position: ",
                Strings.toString(positionId),
                ", Nonce: ",
                Strings.toString(nonce),
                ", Chain: ",
                Strings.toString(block.chainid),
                ", Contract: ",
                Strings.toHexString(contractAddr)
            )
        );
        return message;
    }

    function getSetTpslMsg(uint256 positionId, uint256 tpPrice, uint256 slPrice, uint256 nonce, address contractAddr)
        external
        view
        returns (string memory)
    {
        string memory message = string(
            abi.encodePacked(
                "Set TPSL: ",
                Strings.toString(positionId),
                ", TpPrice: ",
                Strings.toString(tpPrice),
                ", SlPrice: ",
                Strings.toString(slPrice),
                ", Nonce: ",
                Strings.toString(nonce),
                ", Chain: ",
                Strings.toString(block.chainid),
                ", Contract: ",
                Strings.toHexString(contractAddr)
            )
        );
        return message;
    }

    function getChangeMarginMsg(uint256 positionId, bool addMargin, uint256 marginDelta, uint256 nonce, address contractAddr)
        external
        view
        returns (string memory)
    {
        string memory message = string(
            abi.encodePacked(
                "Change Margin for Position: ",
                Strings.toString(positionId),
                ", Add: ",
                Strings.toString(addMargin ? 1 : 0),
                ", Margin: ",
                Strings.toString(marginDelta),
                ", Nonce: ",
                Strings.toString(nonce),
                ", Chain: ",
                Strings.toString(block.chainid),
                ", Contract: ",
                Strings.toHexString(contractAddr)
            )
        );
        return message;
    }

    function _setAdmins(address[] calldata newAdmins, address[] storage admins) external {
        while (admins.length > 0) {
            admins.pop();
        }

        for (uint256 i = 0; i < newAdmins.length; i++) {
            admins.push(newAdmins[i]);
        }
    }
}

library PerpDexLib {
    enum TokenType {
        Btc, // 0
        Klay, // 1
        Wemix, // 2
        Eth, // 3
        Doge, // 4
        Pepe, // 5
        Sol, // 6
        Xrp, // 7
        Apt, // 8
        Sui, // 9
        Shib, // 10
        Sei, // 11
        Ada, // 12
        Pol, // 13
        Bnb, // 14
        Dot, // 15
        Ltc, // 16
        Avax, // 17
        Trump // 18

    }

    enum PositionStatus {
        Initial, // 0
        Open, // 1
        Closed, // 2
        Liquidated, // 3
        RequestOpen, // 4 Deprecated
        LimitOrderOpen, // 5
        LimitOrderClosed, // 6
        RolledBack, // 7
        Merged // 8

    }

    struct Position {
        uint256 positionId;
        address traderAddr;
        TokenType tokenType;
        uint256 margin; // USDT has 6 decimals
        uint256 size;
        uint256 openFee;
        uint256 initialPrice;
        bool isLong;
        uint256 openPositionIndex;
        uint256 finalPrice;
        PositionStatus positionStatus;
        uint256 limitOrderPrice;
        uint256 limitOrderIndex;
        StatusTime statusTime;
        int256 pnl;
        uint256 liquidationPrice; // deprecated
        uint256 tpPrice;
        uint256 slPrice;
        uint256 marginUpdatedTime;
        int256 accFundingFeePerSize;
        int256 fundingFee;
        uint256 closeFee;
        uint256 tpslUpdatedTime;
    }

    struct StatusTime {
        uint256 requestOpenTime; // deprecated
        uint256 openTime;
        uint256 closeTime;
        uint256 limitOpenTime;
        uint256 limitCloseTime;
        uint256 liquidatedTime;
    }

    struct TraderOpenPositionId {
        uint256 longPositionId;
        uint256 shortPositionId;
    }

    struct MergePositions {
        uint256 oldPos; // 0 for no merge
        uint256 newPos;
    }

    enum OracleType {
        BisonAI,
        Pyth
    }

    struct OraclePrices {
        OracleType oracleType;
        bytes32[] feedHashes;
        int256[] answers;
        uint256[] timestamps;
        bytes[] proofs;
    }

    struct TokenTotalSize {
        uint256 maxLong;
        uint256 maxShort;
        uint256 currentLong;
        uint256 currentShort;
    }

    struct OpenPositionData {
        PerpDexLib.TokenType tokenType;
        uint256 marginAmount;
        uint256 leverage;
        bool long;
        address trader;
        PerpDexLib.OraclePrices priceData;
        uint256 tpPrice;
        uint256 slPrice;
        uint256 expectedPrice;
        bytes userSignedData;
    }

    struct OpenLimitOrderData {
        PerpDexLib.TokenType tokenType;
        uint256 marginAmount;
        uint256 leverage;
        bool long;
        address trader;
        uint256 wantedPrice;
        uint256 tpPrice;
        uint256 slPrice;
        bytes userSignedData;
    }

    struct FundingFeeTokenState {
        uint256 lastUpdatedTime;
        int256 lastAppliedRate;
        int256 accFeePerSize; // Funding rate (accFeePerSize) is in Long's perspective. (Short's rate is always the opposite)
    }

    struct FundingFeeGlobalState {
        uint256 bufferBalance;
        uint256 protocolClaimable;
    }

    struct ExternalContracts {
        IFee feeContract;
        ILP lp;
        IERC20 usdt;
    }

    function checkExecutionForLimitOrder(PerpDexLib.Position memory limitOrder, uint256 currentPrice) external pure returns (bool) {
        require(currentPrice > 0, "Price is 0");
        if (limitOrder.isLong) {
            return limitOrder.limitOrderPrice >= currentPrice;
        } else {
            return limitOrder.limitOrderPrice <= currentPrice;
        }
    }

    // for liquidation
    function calculatePnlAndCloseFee(Position memory position, uint256 currentPrice, int256 fundingFee, IFee feeContract)
        public
        view
        returns (int256, uint256)
    {
        uint256 finalValueUsdt = (position.size * currentPrice) / position.initialPrice;
        uint256 initialValueUsdt = position.size;
        int256 pnl;

        if (position.isLong) {
            pnl = int256(finalValueUsdt) - int256(initialValueUsdt);
        } else {
            pnl = int256(initialValueUsdt) - int256(finalValueUsdt);
        }

        uint256 fee;
        if (pnl > 0) {
            uint256 profit = uint256(pnl);
            if (profit > position.margin * 5 || profit > position.size) {
                // Max profit for the trader
                profit = Math.min(position.margin * 5, position.size);
                pnl = int256(profit);
            }

            fee = (position.size + profit) * feeContract.getTotalFeePercent() / feeContract.getFeeDenominator();
        } else {
            if (int256(position.margin) < fundingFee) {
                return (0, 0); // margin < funding fee means liquidation, so pnl and closeFee is 0.
            }

            uint256 loss = Math.min(uint256(int256(position.margin) - fundingFee), uint256(-pnl));
            pnl = -int256(loss);
            fee = (position.size - loss) * feeContract.getTotalFeePercent() / feeContract.getFeeDenominator();
        }

        return (pnl, fee);
    }

    function checkAndLiquidatePosition(
        Position storage position,
        FundingFeeGlobalState storage fundingFeeGlobalState,
        int256 fundingFee,
        int256 pnl,
        uint256 closeFee,
        ExternalContracts memory c
    ) public returns (bool) {
        // 1. Margin pays funding fee first, then close fee.
        int256 marginAfterFundingFee = int256(position.margin) - fundingFee;

        if (marginAfterFundingFee <= 0) {
            // Margin cannot pay for fundingFee
            uint256 deficitFundingFee = uint256(-marginAfterFundingFee);
            require(fundingFeeGlobalState.bufferBalance >= deficitFundingFee, "Funding Fee buffer balance is insufficient");
            fundingFeeGlobalState.bufferBalance -= deficitFundingFee;

            if (pnl > 0) {
                if (pnl > int256(closeFee)) {
                    // Profit can pay for closeFee
                    giveAndRecordProfit(position, uint256(pnl - int256(closeFee)), c.lp);
                    payAndRecordFee(position, closeFee, false, c.feeContract);
                } else {
                    payAndRecordFee(position, uint256(pnl), false, c.feeContract);
                }
            } else {
                // Margin is depleted. No loss to give to LP, no closeFee to collect.
            }

            return true;
        }

        if (marginAfterFundingFee - int256(closeFee) <= 0) {
            // Margin cannot pay for closeFee
            if (pnl > 0) {
                // Profit can pay for the closeFee that margin cannot pay for
                int256 deficitCloseFee = int256(closeFee) - marginAfterFundingFee;
                if (pnl > deficitCloseFee) {
                    // Profit can pay all the deficit amount
                    uint256 profitAfterCloseFee = uint256(pnl - deficitCloseFee);
                    giveAndRecordProfit(position, profitAfterCloseFee, c.lp);
                    payAndRecordFee(position, closeFee, false, c.feeContract);
                } else {
                    payAndRecordFee(position, uint256(marginAfterFundingFee + pnl), false, c.feeContract);
                }
            } else {
                // There is no profit to pay for closeFee
                payAndRecordFee(position, uint256(marginAfterFundingFee), false, c.feeContract);
            }

            return true;
        }

        if (pnl < 0 && marginAfterFundingFee - int256(closeFee) + pnl <= 0) {
            // Margin cannot pay for (closeFee + loss)
            payAndRecordFee(position, closeFee, false, c.feeContract);
            takeAndRecordLoss(position, uint256(marginAfterFundingFee) - closeFee, c.lp, c.usdt);

            return true;
        }

        return false;
    }

    function calculateOpenFee(uint256 inputMarginAmount, uint256 inputLeverage, IFee feeContract) public view returns (uint256) {
        uint256 inputSize = inputMarginAmount * inputLeverage;
        uint256 fee = inputSize * feeContract.getTotalFeePercent() / feeContract.getFeeDenominator();
        return fee;
    }

    function getFundingFeeScalingFactor() internal pure returns (int256) {
        return 1e20;
    }

    function calculateFundingFee(Position storage position, FundingFeeTokenState storage fundingFeeTokenState)
        public
        view
        returns (int256)
    {
        int256 newFundingFee =
            int256(position.size) * (fundingFeeTokenState.accFeePerSize - position.accFundingFeePerSize) / getFundingFeeScalingFactor();

        return position.fundingFee + (position.isLong ? newFundingFee : -newFundingFee);
    }

    function _addInitialTokenTotalSizes(TokenTotalSize[] storage tokenTotalSizes, uint256 count) external {
        for (uint256 i = 0; i < count; i++) {
            tokenTotalSizes.push(PerpDexLib.TokenTotalSize(0, 0, 0, 0));
        }
    }

    function _changeMaxTokenTotalSizes(TokenTotalSize[] storage tokenTotalSizes) external {
        // according to TokenType
        tokenTotalSizes[0] = TokenTotalSize({
            maxLong: 300_000_000_000,
            maxShort: 300_000_000_000,
            currentLong: tokenTotalSizes[0].currentLong,
            currentShort: tokenTotalSizes[0].currentShort
        });
        tokenTotalSizes[1] = TokenTotalSize({
            maxLong: 75_000_000_000,
            maxShort: 75_000_000_000,
            currentLong: tokenTotalSizes[1].currentLong,
            currentShort: tokenTotalSizes[1].currentShort
        });
        tokenTotalSizes[2] = TokenTotalSize({ // Wemix is deprecated
            maxLong: 0,
            maxShort: 0,
            currentLong: tokenTotalSizes[2].currentLong,
            currentShort: tokenTotalSizes[2].currentShort
        });
        tokenTotalSizes[3] = TokenTotalSize({
            maxLong: 300_000_000_000,
            maxShort: 300_000_000_000,
            currentLong: tokenTotalSizes[3].currentLong,
            currentShort: tokenTotalSizes[3].currentShort
        });
        tokenTotalSizes[4] = TokenTotalSize({
            maxLong: 120_000_000_000,
            maxShort: 120_000_000_000,
            currentLong: tokenTotalSizes[4].currentLong,
            currentShort: tokenTotalSizes[4].currentShort
        });
        tokenTotalSizes[5] = TokenTotalSize({
            maxLong: 120_000_000_000,
            maxShort: 120_000_000_000,
            currentLong: tokenTotalSizes[5].currentLong,
            currentShort: tokenTotalSizes[5].currentShort
        });
        tokenTotalSizes[6] = TokenTotalSize({
            maxLong: 250_000_000_000,
            maxShort: 250_000_000_000,
            currentLong: tokenTotalSizes[6].currentLong,
            currentShort: tokenTotalSizes[6].currentShort
        });
        tokenTotalSizes[7] = TokenTotalSize({
            maxLong: 200_000_000_000,
            maxShort: 200_000_000_000,
            currentLong: tokenTotalSizes[7].currentLong,
            currentShort: tokenTotalSizes[7].currentShort
        });
        tokenTotalSizes[8] = TokenTotalSize({
            maxLong: 200_000_000_000,
            maxShort: 200_000_000_000,
            currentLong: tokenTotalSizes[8].currentLong,
            currentShort: tokenTotalSizes[8].currentShort
        });
        tokenTotalSizes[9] = TokenTotalSize({
            maxLong: 200_000_000_000,
            maxShort: 200_000_000_000,
            currentLong: tokenTotalSizes[9].currentLong,
            currentShort: tokenTotalSizes[9].currentShort
        });
        tokenTotalSizes[10] = TokenTotalSize({
            maxLong: 120_000_000_000,
            maxShort: 120_000_000_000,
            currentLong: tokenTotalSizes[10].currentLong,
            currentShort: tokenTotalSizes[10].currentShort
        });
        tokenTotalSizes[11] = TokenTotalSize({
            maxLong: 150_000_000_000,
            maxShort: 150_000_000_000,
            currentLong: tokenTotalSizes[11].currentLong,
            currentShort: tokenTotalSizes[11].currentShort
        });
        tokenTotalSizes[12] = TokenTotalSize({
            maxLong: 250_000_000_000,
            maxShort: 250_000_000_000,
            currentLong: tokenTotalSizes[12].currentLong,
            currentShort: tokenTotalSizes[12].currentShort
        });
        tokenTotalSizes[13] = TokenTotalSize({
            maxLong: 200_000_000_000,
            maxShort: 200_000_000_000,
            currentLong: tokenTotalSizes[13].currentLong,
            currentShort: tokenTotalSizes[13].currentShort
        });
        tokenTotalSizes[14] = TokenTotalSize({
            maxLong: 250_000_000_000,
            maxShort: 250_000_000_000,
            currentLong: tokenTotalSizes[14].currentLong,
            currentShort: tokenTotalSizes[14].currentShort
        });
        tokenTotalSizes[15] = TokenTotalSize({
            maxLong: 200_000_000_000,
            maxShort: 200_000_000_000,
            currentLong: tokenTotalSizes[15].currentLong,
            currentShort: tokenTotalSizes[15].currentShort
        });
        tokenTotalSizes[16] = TokenTotalSize({
            maxLong: 250_000_000_000,
            maxShort: 250_000_000_000,
            currentLong: tokenTotalSizes[16].currentLong,
            currentShort: tokenTotalSizes[16].currentShort
        });
        tokenTotalSizes[17] = TokenTotalSize({
            maxLong: 250_000_000_000,
            maxShort: 250_000_000_000,
            currentLong: tokenTotalSizes[17].currentLong,
            currentShort: tokenTotalSizes[17].currentShort
        });

        tokenTotalSizes[18] = TokenTotalSize({
            maxLong: 100_000_000_000,
            maxShort: 100_000_000_000,
            currentLong: tokenTotalSizes[18].currentLong,
            currentShort: tokenTotalSizes[18].currentShort
        });
    }

    function updateTraderOpenPositionId(bool isLong, uint256 positionId, TraderOpenPositionId storage traderOpenPositionId) public {
        if (isLong) {
            require(traderOpenPositionId.longPositionId == 0, "Long position already exists");
            traderOpenPositionId.longPositionId = positionId;
        } else {
            require(traderOpenPositionId.shortPositionId == 0, "Short position already exists");
            traderOpenPositionId.shortPositionId = positionId;
        }
    }

    function clearTraderOpenPositionId(bool isLong, TraderOpenPositionId storage traderOpenPositionId) internal {
        if (isLong) {
            traderOpenPositionId.longPositionId = 0;
        } else {
            traderOpenPositionId.shortPositionId = 0;
        }
    }

    function findPositionToMerge(bool isLong, TraderOpenPositionId storage traderOpenPositionId) public view returns (uint256) {
        if (isLong) {
            return traderOpenPositionId.longPositionId;
        } else {
            return traderOpenPositionId.shortPositionId;
        }
    }

    function cleanUpPosition(
        mapping(uint256 => Position) storage positions,
        uint256[] storage openPositionIds,
        uint256 positionId,
        uint256 closingPrice,
        PerpDexLib.PositionStatus positionStatus,
        TraderOpenPositionId storage traderOpenPositionId
    ) public {
        PerpDexLib.Position storage position = positions[positionId];
        // Keep closed positions
        require(closingPrice > 0, "Price is 0");
        require(openPositionIds.length > 0, "No open positions");
        require(position.openPositionIndex < openPositionIds.length, "Invalid position index");

        if (position.openPositionIndex != openPositionIds.length - 1) {
            uint256 shiftingPositionId = openPositionIds[openPositionIds.length - 1];
            PerpDexLib.Position storage shiftingPosition = positions[shiftingPositionId];
            shiftingPosition.openPositionIndex = position.openPositionIndex;
            openPositionIds[position.openPositionIndex] = shiftingPositionId;
        }

        openPositionIds.pop();
        clearTraderOpenPositionId(position.isLong, traderOpenPositionId);

        if (positionStatus == PerpDexLib.PositionStatus.Closed || positionStatus == PerpDexLib.PositionStatus.RolledBack) {
            position.statusTime.closeTime = block.timestamp;
        } else if (positionStatus == PerpDexLib.PositionStatus.Liquidated) {
            position.statusTime.liquidatedTime = block.timestamp;
        } else {
            // Should not happen
            revert("Wrong position status");
        }

        position.positionStatus = positionStatus;
        position.finalPrice = closingPrice;
        position.openPositionIndex = type(uint256).max;
    }

    function cleanUpLimitOrder(mapping(uint256 => Position) storage positions, uint256[] storage limitOrderIds, uint256 positionId)
        public
    {
        Position storage limitOrderPositionToDelete = positions[positionId];
        require(limitOrderIds.length > 0, "No limit orders");
        require(limitOrderPositionToDelete.limitOrderIndex < limitOrderIds.length, "Invalid limit order index"); // Should not happen

        if (limitOrderPositionToDelete.limitOrderIndex != limitOrderIds.length - 1) {
            uint256 shiftingLimitOrderId = limitOrderIds[limitOrderIds.length - 1];
            PerpDexLib.Position storage shiftingLimitOrderPosition = positions[shiftingLimitOrderId];
            shiftingLimitOrderPosition.limitOrderIndex = limitOrderPositionToDelete.limitOrderIndex;
            limitOrderIds[limitOrderPositionToDelete.limitOrderIndex] = shiftingLimitOrderId;
        }

        limitOrderIds.pop();

        limitOrderPositionToDelete.limitOrderIndex = type(uint256).max;
    }

    function checkPositionSizeAndIncrease(TokenTotalSize[] storage tokenTotalSizes, TokenType tokenType, bool isLong, uint256 size)
        public
        returns (bool)
    {
        TokenTotalSize storage sizeInfo = tokenTotalSizes[uint256(tokenType)];
        if (isLong) {
            if (sizeInfo.currentLong + size > sizeInfo.maxLong) {
                return false;
            }
            sizeInfo.currentLong += size;
            return true;
        } else {
            if (sizeInfo.currentShort + size > sizeInfo.maxShort) {
                return false;
            }
            sizeInfo.currentShort += size;
            return true;
        }
    }

    function decreaseTotalPositionSize(TokenTotalSize[] storage tokenTotalSizes, TokenType tokenType, bool isLong, uint256 size) public {
        TokenTotalSize storage sizeInfo = tokenTotalSizes[uint256(tokenType)];
        if (isLong) {
            sizeInfo.currentLong -= size;
        } else {
            sizeInfo.currentShort -= size;
        }
    }

    function mergePosition(
        mapping(uint256 => Position) storage positions,
        FundingFeeTokenState storage fundingFeeTokenState,
        FundingFeeGlobalState storage fundingFeeGlobalState,
        ExternalContracts memory c,
        PerpDexLib.MergePositions memory mergePos,
        uint256 currentPrice
    ) public {
        Position storage oldPosition = positions[mergePos.oldPos];
        Position storage newPosition = positions[mergePos.newPos];

        require(
            (newPosition.statusTime.openTime == block.timestamp && newPosition.positionStatus == PositionStatus.Open)
                || newPosition.positionStatus == PositionStatus.LimitOrderOpen,
            "Position to merge must be being newly open or opened by limit order"
        );
        require(oldPosition.positionStatus == PositionStatus.Open, "Old position status is not Open");
        require(currentPrice > 0, "Price is 0");
        require(newPosition.traderAddr == oldPosition.traderAddr, "Trader is different");
        require(newPosition.tokenType == oldPosition.tokenType, "TokenType is different");
        require(newPosition.isLong == oldPosition.isLong, "IsLong is different");
        require(oldPosition.statusTime.openTime <= block.timestamp, "Old position status time is not correct");

        // check if old position is liquidatable
        int256 fundingFee = calculateFundingFee(oldPosition, fundingFeeTokenState);
        (int256 pnl, uint256 closeFee) = calculatePnlAndCloseFee(oldPosition, currentPrice, fundingFee, c.feeContract);
        require(!checkAndLiquidatePosition(oldPosition, fundingFeeGlobalState, fundingFee, pnl, closeFee, c), "Position will be liquidated");
        oldPosition.fundingFee = fundingFee;
        oldPosition.accFundingFeePerSize = newPosition.accFundingFeePerSize;

        oldPosition.initialPrice = oldPosition.initialPrice * currentPrice * (oldPosition.size + newPosition.size)
            / (currentPrice * oldPosition.size + oldPosition.initialPrice * newPosition.size);
        oldPosition.margin += newPosition.margin;
        oldPosition.size += newPosition.size;
        oldPosition.statusTime.openTime = block.timestamp;

        if (newPosition.tpPrice > 0) {
            oldPosition.tpPrice = newPosition.tpPrice;
        }
        if (newPosition.slPrice > 0) {
            oldPosition.slPrice = newPosition.slPrice;
        }
        oldPosition.tpslUpdatedTime = block.timestamp;

        newPosition.positionStatus = PositionStatus.Merged;
        newPosition.statusTime.openTime = block.timestamp;
        newPosition.initialPrice = currentPrice;

        payAndRecordFee(oldPosition, newPosition.openFee, true, c.feeContract);
        emit PerpDex.PositionMerged(
            oldPosition.positionId,
            newPosition.positionId,
            oldPosition.traderAddr,
            oldPosition.tokenType,
            oldPosition.margin,
            oldPosition.size,
            oldPosition.initialPrice,
            oldPosition.isLong,
            oldPosition.tpPrice,
            oldPosition.slPrice,
            oldPosition.fundingFee
        );
    }

    function createLimitOrder(uint256 positionId, PerpDexLib.OpenLimitOrderData memory o, uint256 limitOrderIdLength, IFee feeContract)
        internal
        view
        returns (Position memory)
    {
        require(o.wantedPrice > 0, "Price is 0");
        require(o.leverage >= 3 && o.leverage <= 100, "Leverage must be within range");

        uint256 fee = calculateOpenFee(o.marginAmount, o.leverage, feeContract);
        uint256 marginAfterFee = o.marginAmount - fee;

        PerpDexLib.StatusTime memory statusTime = PerpDexLib.StatusTime({
            requestOpenTime: 0,
            openTime: 0,
            closeTime: 0,
            limitOpenTime: block.timestamp,
            limitCloseTime: 0,
            liquidatedTime: 0
        });

        PerpDexLib.Position memory newPosition = PerpDexLib.Position({
            positionId: positionId,
            traderAddr: o.trader,
            tokenType: o.tokenType,
            margin: marginAfterFee,
            size: marginAfterFee * o.leverage,
            openFee: fee, // Fee is paid later when limitOrder is opened.
            initialPrice: 0,
            isLong: o.long,
            openPositionIndex: type(uint256).max,
            finalPrice: 0,
            positionStatus: PerpDexLib.PositionStatus.LimitOrderOpen,
            limitOrderPrice: o.wantedPrice,
            limitOrderIndex: limitOrderIdLength,
            statusTime: statusTime,
            pnl: 0,
            liquidationPrice: 0,
            tpPrice: o.tpPrice,
            slPrice: o.slPrice,
            marginUpdatedTime: 0,
            accFundingFeePerSize: 0,
            fundingFee: 0,
            closeFee: 0,
            tpslUpdatedTime: block.timestamp
        });

        return newPosition;
    }

    function createNewPosition(
        uint256 positionId,
        OpenPositionData calldata o,
        uint256 initialPrice,
        uint256 openPositionIdLength,
        int256 accFundingFeePerSize,
        TokenTotalSize[] storage tokenTotalSizes,
        IFee feeContract
    ) external returns (Position memory) {
        uint256 fee = calculateOpenFee(o.marginAmount, o.leverage, feeContract);
        uint256 marginAfterFee = o.marginAmount - fee;
        uint256 size = marginAfterFee * o.leverage;

        require(o.leverage >= 3 && o.leverage <= 100, "Leverage must be within range");

        if (!checkPositionSizeAndIncrease(tokenTotalSizes, o.tokenType, o.long, size)) {
            revert("Maximum position size reached");
        }

        PerpDexLib.StatusTime memory statusTime = PerpDexLib.StatusTime({
            requestOpenTime: 0,
            openTime: block.timestamp,
            closeTime: 0,
            limitOpenTime: 0,
            limitCloseTime: 0,
            liquidatedTime: 0
        });

        PerpDexLib.Position memory newPosition = PerpDexLib.Position({
            positionId: positionId,
            traderAddr: o.trader,
            tokenType: o.tokenType,
            margin: marginAfterFee,
            size: size,
            openFee: fee,
            initialPrice: initialPrice,
            isLong: o.long,
            openPositionIndex: openPositionIdLength,
            finalPrice: 0,
            positionStatus: PerpDexLib.PositionStatus.Open,
            limitOrderPrice: 0,
            limitOrderIndex: type(uint256).max,
            statusTime: statusTime,
            pnl: 0,
            liquidationPrice: 0,
            tpPrice: o.tpPrice,
            slPrice: o.slPrice,
            marginUpdatedTime: 0,
            accFundingFeePerSize: accFundingFeePerSize,
            fundingFee: 0,
            closeFee: 0,
            tpslUpdatedTime: block.timestamp
        });

        return newPosition;
    }

    function payAndRecordFee(Position storage position, uint256 fee, bool isOpen, IFee feeContract) internal {
        feeContract.payFee(position.traderAddr, fee);
        if (isOpen) {
            position.openFee += fee;
        } else {
            position.closeFee += fee;
        }
    }

    function giveAndRecordProfit(Position storage position, uint256 profit, ILP lp) internal {
        lp.giveProfit(position.traderAddr, profit);
        position.pnl = int256(profit);
    }

    function takeAndRecordLoss(Position storage position, uint256 loss, ILP lp, IERC20 usdt) internal {
        PerpDexPricesLib.safeTransferAndCheckBalance(address(lp), loss, usdt);
        position.pnl = -int256(loss);
    }

    function _closePosition(
        mapping(uint256 => Position) storage positions,
        uint256 positionId,
        FundingFeeTokenState storage fundingFeeTokenState,
        FundingFeeGlobalState storage fundingFeeGlobalState,
        mapping(address => mapping(uint16 => TraderOpenPositionId)) storage traderOpenPositionIds,
        TokenTotalSize[] storage tokenTotalSizes,
        uint256[] storage openPositionIds,
        uint256 closingPrice,
        ExternalContracts memory c
    ) external {
        require(closingPrice > 0, "Price is 0");

        Position storage position = positions[positionId];
        if (position.positionStatus != PerpDexLib.PositionStatus.Open) revert InvalidPositionStatus();

        updateFundingFeeState(position.tokenType, fundingFeeTokenState, fundingFeeGlobalState, tokenTotalSizes[uint256(position.tokenType)]);

        // funding Fee
        int256 fundingFee = calculateFundingFee(position, fundingFeeTokenState);

        // pnl and closeFee
        (int256 pnl, uint256 closeFee) = calculatePnlAndCloseFee(position, closingPrice, fundingFee, c.feeContract);
        bool isLiquidated = checkAndLiquidatePosition(position, fundingFeeGlobalState, fundingFee, pnl, closeFee, c);

        position.fundingFee = fundingFee;

        if (isLiquidated) {
            // already updated pnl and fee in checkAndLiquidatePosition
        } else {
            int256 marginAfterFundingFee = int256(position.margin) - fundingFee;
            if (pnl > 0) {
                payAndRecordFee(position, closeFee, false, c.feeContract);
                PerpDexPricesLib.safeTransferAndCheckBalance(position.traderAddr, uint256(marginAfterFundingFee) - closeFee, c.usdt);
                giveAndRecordProfit(position, uint256(pnl), c.lp);
            } else {
                uint256 loss = uint256(-pnl);
                payAndRecordFee(position, closeFee, false, c.feeContract);
                PerpDexPricesLib.safeTransferAndCheckBalance(position.traderAddr, uint256(marginAfterFundingFee) - closeFee - loss, c.usdt);
                takeAndRecordLoss(position, uint256(-pnl), c.lp, c.usdt);
            }
        }

        decreaseTotalPositionSize(tokenTotalSizes, position.tokenType, position.isLong, position.size);
        cleanUpPosition(
            positions,
            openPositionIds,
            position.positionId,
            closingPrice,
            isLiquidated ? PositionStatus.Liquidated : PositionStatus.Closed,
            traderOpenPositionIds[position.traderAddr][uint16(position.tokenType)]
        );

        emit PerpDex.PositionClosed(
            position.positionId,
            position.traderAddr,
            position.tokenType,
            position.margin,
            position.size,
            position.initialPrice,
            position.isLong,
            position.finalPrice,
            position.fundingFee
        );
    }

    function _setTpslPrice(Position storage position, uint256 tpPrice, uint256 slPrice) external {
        require(
            position.positionStatus == PerpDexLib.PositionStatus.Open || position.positionStatus == PerpDexLib.PositionStatus.LimitOrderOpen,
            "Position is not open"
        );

        position.tpPrice = tpPrice;
        position.slPrice = slPrice;
        position.tpslUpdatedTime = block.timestamp;

        emit PerpDex.TPSLSet(position.positionId, position.traderAddr, tpPrice, slPrice);
    }

    function _changeMargin(
        Position storage position,
        FundingFeeTokenState storage fundingFeeTokenState,
        FundingFeeGlobalState storage fundingFeeGlobalState,
        TokenTotalSize storage tokenTotalSize,
        bool addMargin,
        uint256 marginDelta,
        uint256 currentPrice,
        ExternalContracts memory c
    ) external {
        require(position.positionStatus == PerpDexLib.PositionStatus.Open, "Position is not open");

        updateFundingFeeState(position.tokenType, fundingFeeTokenState, fundingFeeGlobalState, tokenTotalSize);

        int256 fundingFee = calculateFundingFee(position, fundingFeeTokenState);
        (int256 pnl, uint256 closeFee) = calculatePnlAndCloseFee(position, currentPrice, fundingFee, c.feeContract);
        require(!checkAndLiquidatePosition(position, fundingFeeGlobalState, fundingFee, pnl, closeFee, c), "Position will be liquidated");

        if (!addMargin) {
            require(position.margin > marginDelta, "Margin to remove is greater than margin");
            require(
                pnl > 0
                    ? int256(position.margin - marginDelta) - fundingFee - int256(closeFee) > 0
                    : int256(position.margin - marginDelta) - fundingFee - int256(closeFee) - pnl > 0,
                "Position will be liquidated after margin is removed"
            );
        }

        uint256 fee = marginDelta * c.feeContract.getMarginFeePercent() / c.feeContract.getFeeDenominator();
        require(fee > 0, "Margin added is too small");

        position.margin = addMargin ? position.margin + marginDelta - fee : position.margin - marginDelta;
        position.marginUpdatedTime = block.timestamp;

        uint256 factor = 1e6;
        uint256 leverage = position.size * factor / position.margin;
        require(0 <= leverage && leverage <= 100 * factor, "Leverage is out of boundary");

        if (addMargin) {
            PerpDexPricesLib.safeTransferFromAndCheckBalance(position.traderAddr, address(this), marginDelta, c.usdt);
        } else {
            PerpDexPricesLib.safeTransferAndCheckBalance(position.traderAddr, marginDelta - fee, c.usdt);
        }

        payAndRecordFee(position, fee, true, c.feeContract);
        emit PerpDex.PositionMarginChanged(position.positionId, position.traderAddr, position.tokenType, addMargin, marginDelta);
    }

    function updateFundingFeeState(
        PerpDexLib.TokenType tokenType,
        FundingFeeTokenState storage fundingFeeState,
        FundingFeeGlobalState storage fundingFeeGlobalState,
        TokenTotalSize storage tokenTotalSize
    ) public {
        int256 SCALING_FACTOR = getFundingFeeScalingFactor();
        int256 COEFFICIENT_DECIMAL_FACTOR = 1e7;
        int256 COEFFICIENT = 875;
        int256 COEFFICIENT_TIME_FACTOR = 3600; // coefficient 0.021% for 1 hour

        int256 long = int256(tokenTotalSize.currentLong);
        int256 short = int256(tokenTotalSize.currentShort);

        int256 fundingRate = (long == 0 && short == 0)
            ? int256(0)
            : (SCALING_FACTOR / COEFFICIENT_DECIMAL_FACTOR) * COEFFICIENT * (long - short) / (long + short);
        int256 timeDelta = (fundingFeeState.lastUpdatedTime == 0) ? int256(0) : int256(block.timestamp - fundingFeeState.lastUpdatedTime);

        int256 timeWeightedFundingRate = fundingRate * timeDelta / COEFFICIENT_TIME_FACTOR;

        fundingFeeState.accFeePerSize += timeWeightedFundingRate;
        fundingFeeState.lastAppliedRate = fundingRate;
        fundingFeeState.lastUpdatedTime = block.timestamp;

        fundingFeeGlobalState.protocolClaimable += uint256(timeWeightedFundingRate * (long - short));

        emit PerpDex.FundingFeeStateUpdated(block.timestamp, tokenType, fundingRate, fundingFeeState.accFeePerSize, long, short);
    }

    function _openPosition(
        PerpDexLib.OpenPositionData calldata o,
        uint256 currentPrice,
        uint256 positionId,
        mapping(uint256 => PerpDexLib.Position) storage positions,
        PerpDexLib.FundingFeeGlobalState storage fundingFeeGlobalState,
        mapping(PerpDexLib.TokenType => PerpDexLib.FundingFeeTokenState) storage fundingFeeTokenStates,
        mapping(address => mapping(uint16 => PerpDexLib.TraderOpenPositionId)) storage traderOpenPositionIds,
        uint256[] storage openPositionIds,
        PerpDexLib.ExternalContracts calldata c
    ) external {
        Position storage newPosition = positions[positionId];

        uint256 oldPosForMerge =
            findPositionToMerge(newPosition.isLong, traderOpenPositionIds[newPosition.traderAddr][uint16(newPosition.tokenType)]);

        if (oldPosForMerge == 0) {
            openPositionIds.push(positionId);
            updateTraderOpenPositionId(
                newPosition.isLong, positionId, traderOpenPositionIds[newPosition.traderAddr][uint16(newPosition.tokenType)]
            );

            c.feeContract.payFee(o.trader, newPosition.openFee);

            emit PerpDex.PositionOpened(
                newPosition.positionId,
                newPosition.traderAddr,
                newPosition.tokenType,
                newPosition.margin,
                newPosition.size,
                newPosition.initialPrice,
                newPosition.isLong,
                newPosition.tpPrice,
                newPosition.slPrice
            );
        } else {
            mergePosition(
                positions,
                fundingFeeTokenStates[newPosition.tokenType],
                fundingFeeGlobalState,
                c,
                PerpDexLib.MergePositions(oldPosForMerge, positionId),
                currentPrice
            );
        }
    }

    function _openLimitOrder(
        OpenLimitOrderData calldata o,
        uint256 positionId,
        mapping(uint256 => Position) storage positions,
        mapping(address => uint256[]) storage traderPositionIds,
        uint256[] storage limitOrderIds,
        ExternalContracts calldata c
    ) external {
        if (positions[positionId].positionStatus != PositionStatus.Initial) revert NextPositionIdExists(); // Should not happen

        Position memory newPosition = createLimitOrder(positionId, o, limitOrderIds.length, c.feeContract);

        positions[positionId] = newPosition;
        traderPositionIds[o.trader].push(positionId);
        limitOrderIds.push(positionId);

        PerpDexPricesLib.safeTransferFromAndCheckBalance(o.trader, address(this), o.marginAmount, c.usdt);
        emit PerpDex.LimitOrderOpened(
            positionId,
            newPosition.traderAddr,
            newPosition.tokenType,
            newPosition.margin,
            newPosition.size,
            newPosition.limitOrderPrice,
            newPosition.isLong,
            newPosition.tpPrice,
            newPosition.slPrice
        );
    }

    function _closeLimitOrder(
        Position storage order,
        mapping(uint256 => Position) storage positions,
        uint256[] storage limitOrderIds,
        ExternalContracts calldata c
    ) external {
        if (order.positionStatus != PerpDexLib.PositionStatus.LimitOrderOpen) revert InvalidPositionStatus();

        order.positionStatus = PerpDexLib.PositionStatus.LimitOrderClosed;
        order.statusTime.limitCloseTime = block.timestamp;
        cleanUpLimitOrder(positions, limitOrderIds, order.positionId);

        PerpDexPricesLib.safeTransferAndCheckBalance(order.traderAddr, order.margin + order.openFee, c.usdt);
        emit PerpDex.LimitOrderClosed(order.positionId, order.traderAddr);
    }
}

library PerpDexBotLib {
    function openPositionForLimitOrder(
        PerpDexLib.Position storage position,
        uint256 currentPrice,
        uint256[] storage openPositionIds,
        PerpDexLib.TraderOpenPositionId storage traderOpenPositionId,
        int256 accFundingFeePerSize,
        IFee feeContract
    ) public {
        require(currentPrice > 0, "Price is 0");

        require(position.positionStatus == PerpDexLib.PositionStatus.LimitOrderOpen, "Status is not limit order open"); // Should not happen

        position.initialPrice = currentPrice;
        position.openPositionIndex = openPositionIds.length;
        position.positionStatus = PerpDexLib.PositionStatus.Open;
        position.statusTime.openTime = block.timestamp;

        position.accFundingFeePerSize = accFundingFeePerSize;

        openPositionIds.push(position.positionId);
        PerpDexLib.updateTraderOpenPositionId(position.isLong, position.positionId, traderOpenPositionId);

        feeContract.payFee(position.traderAddr, position.openFee);
        emit PerpDex.PositionOpened(
            position.positionId,
            position.traderAddr,
            position.tokenType,
            position.margin,
            position.size,
            position.initialPrice,
            position.isLong,
            position.tpPrice,
            position.slPrice
        );
    }

    function _executeLimitOrder(
        mapping(uint256 => PerpDexLib.Position) storage positions,
        uint256 orderId,
        mapping(PerpDexLib.TokenType => PerpDexLib.FundingFeeTokenState) storage fundingFeeTokenStates,
        mapping(address => mapping(uint16 => PerpDexLib.TraderOpenPositionId)) storage traderOpenPositionIds,
        PerpDexLib.FundingFeeGlobalState storage fundingFeeGlobalState,
        PerpDexLib.TokenTotalSize[] storage tokenTotalSizes,
        uint256[] storage openPositionIds,
        PerpDexLib.ExternalContracts calldata c,
        uint256 price,
        uint256[] storage limitOrderIds
    ) external {
        PerpDexLib.Position storage order = positions[orderId];
        PerpDexLib.updateFundingFeeState(
            order.tokenType, fundingFeeTokenStates[order.tokenType], fundingFeeGlobalState, tokenTotalSizes[uint256(order.tokenType)]
        );

        if (!PerpDexLib.checkPositionSizeAndIncrease(tokenTotalSizes, order.tokenType, order.isLong, order.size)) {
            return;
        }
        uint256 oldPosForMerge =
            PerpDexLib.findPositionToMerge(order.isLong, traderOpenPositionIds[order.traderAddr][uint16(order.tokenType)]);

        if (oldPosForMerge == 0) {
            openPositionForLimitOrder(
                order,
                price,
                openPositionIds,
                traderOpenPositionIds[order.traderAddr][uint16(order.tokenType)],
                fundingFeeTokenStates[order.tokenType].accFeePerSize,
                c.feeContract
            );
        } else {
            PerpDexLib.mergePosition(
                positions,
                fundingFeeTokenStates[order.tokenType],
                fundingFeeGlobalState,
                c,
                PerpDexLib.MergePositions(oldPosForMerge, order.positionId),
                price
            );
        }
        PerpDexLib.cleanUpLimitOrder(positions, limitOrderIds, order.positionId);
        emit PerpDex.LimitOrderExecuted(order.positionId, order.traderAddr);
    }

    function decreaseSizeAndCleanUpOnLiquidate(
        mapping(uint256 => PerpDexLib.Position) storage positions,
        uint256 positionId,
        mapping(address => mapping(uint16 => PerpDexLib.TraderOpenPositionId)) storage traderOpenPositionIds,
        PerpDexLib.TokenTotalSize[] storage tokenTotalSizes,
        uint256[] storage openPositionIds,
        uint256 price
    ) internal {
        PerpDexLib.Position storage position = positions[positionId];
        PerpDexLib.decreaseTotalPositionSize(tokenTotalSizes, position.tokenType, position.isLong, position.size);
        PerpDexLib.cleanUpPosition(
            positions,
            openPositionIds,
            position.positionId,
            price,
            PerpDexLib.PositionStatus.Liquidated,
            traderOpenPositionIds[position.traderAddr][uint16(position.tokenType)]
        );

        emit PerpDex.PositionLiquidated(
            position.positionId,
            position.traderAddr,
            position.tokenType,
            position.margin,
            position.size,
            position.initialPrice,
            position.isLong,
            position.finalPrice,
            position.fundingFee
        );
    }

    function _liquidatePosition(
        mapping(uint256 => PerpDexLib.Position) storage positions,
        uint256 positionId,
        mapping(PerpDexLib.TokenType => PerpDexLib.FundingFeeTokenState) storage fundingFeeTokenStates,
        mapping(address => mapping(uint16 => PerpDexLib.TraderOpenPositionId)) storage traderOpenPositionIds,
        PerpDexLib.FundingFeeGlobalState storage fundingFeeGlobalState,
        PerpDexLib.TokenTotalSize[] storage tokenTotalSizes,
        uint256[] storage openPositionIds,
        PerpDexLib.ExternalContracts calldata c,
        uint256 price
    ) external {
        PerpDexLib.Position storage position = positions[positionId];
        PerpDexLib.updateFundingFeeState(
            position.tokenType,
            fundingFeeTokenStates[position.tokenType],
            fundingFeeGlobalState,
            tokenTotalSizes[uint256(position.tokenType)]
        );
        int256 fundingFee = PerpDexLib.calculateFundingFee(position, fundingFeeTokenStates[position.tokenType]);
        (int256 pnl, uint256 closeFee) = PerpDexLib.calculatePnlAndCloseFee(position, price, fundingFee, c.feeContract);
        if (!PerpDexLib.checkAndLiquidatePosition(position, fundingFeeGlobalState, fundingFee, pnl, closeFee, c)) {
            return;
        }

        position.fundingFee = fundingFee;

        decreaseSizeAndCleanUpOnLiquidate(positions, positionId, traderOpenPositionIds, tokenTotalSizes, openPositionIds, price);
    }

    function _tpslClosePosition(
        mapping(uint256 => PerpDexLib.Position) storage positions,
        uint256 positionId,
        mapping(PerpDexLib.TokenType => PerpDexLib.FundingFeeTokenState) storage fundingFeeTokenStates,
        mapping(address => mapping(uint16 => PerpDexLib.TraderOpenPositionId)) storage traderOpenPositionIds,
        PerpDexLib.FundingFeeGlobalState storage fundingFeeGlobalState,
        PerpDexLib.TokenTotalSize[] storage tokenTotalSizes,
        uint256[] storage openPositionIds,
        PerpDexLib.ExternalContracts calldata c,
        uint256 price,
        uint256 updatedAt
    ) external {
        PerpDexLib.Position storage position = positions[positionId];

        bool shouldClose = position.isLong
            ? (position.slPrice > 0 && price <= position.slPrice) || (position.tpPrice > 0 && price >= position.tpPrice)
            : (position.slPrice > 0 && price >= position.slPrice) || (position.tpPrice > 0 && price <= position.tpPrice);

        if (position.statusTime.openTime < updatedAt && position.tpslUpdatedTime < updatedAt && shouldClose) {
            PerpDexLib._closePosition(
                positions,
                positionId,
                fundingFeeTokenStates[position.tokenType],
                fundingFeeGlobalState,
                traderOpenPositionIds,
                tokenTotalSizes,
                openPositionIds,
                price,
                c
            );
        }
    }
}

contract PerpDex is Initializable, PausableUpgradeable, OwnableUpgradeable, UUPSUpgradeable, ReentrancyGuardUpgradeable {
    IBisonAIRouter bisonAIRouter; // set this to QA address for test. (for liquidation/limit order)
    IBisonAISubmissionProxy bisonAISubmissionProxy;
    IPyth pyth;
    PerpDexLib.ExternalContracts externalContracts;

    address admin; // protocol fee and funding fee collector
    mapping(PerpDexAuthLib.AdminType => address[]) adminsByRole;

    mapping(address => uint256) public traderNonce;
    uint256 public nextPositionId = 1; // 0 is a placeholder

    mapping(uint256 => PerpDexLib.Position) positions;
    mapping(address => uint256[]) traderPositionIds;
    mapping(address => mapping(uint16 => PerpDexLib.TraderOpenPositionId)) traderOpenPositionIds;
    uint256[] openPositionIds;
    uint256[] limitOrderIds;

    PerpDexLib.FundingFeeGlobalState public fundingFeeGlobalState;
    mapping(PerpDexLib.TokenType => PerpDexLib.FundingFeeTokenState) public fundingFeeTokenStates;

    PerpDexLib.TokenTotalSize[] public tokenTotalSizes;

    event SubmittedRoundId(PerpDexLib.TokenType indexed tokenType, uint64 indexed roundId);

    event PositionMerged(
        uint256 indexed positionId,
        uint256 indexed newPositionId,
        address indexed traderAddr,
        PerpDexLib.TokenType tokenType,
        uint256 margin,
        uint256 size,
        uint256 initialPrice,
        bool isLong,
        uint256 tpPrice,
        uint256 slPrice,
        int256 fundingFee
    );

    event PositionOpened(
        uint256 indexed positionId,
        address indexed traderAddr,
        PerpDexLib.TokenType indexed tokenType,
        uint256 margin,
        uint256 size,
        uint256 initialPrice,
        bool isLong,
        uint256 tpPrice,
        uint256 slPrice
    );

    event PositionMarginChanged(
        uint256 indexed positionId, address indexed traderAddr, PerpDexLib.TokenType indexed tokenType, bool addMargin, uint256 marginDelta
    );

    event TPSLSet(uint256 indexed positionId, address indexed traderAddr, uint256 tpPrice, uint256 slPrice);

    event FundingFeeStateUpdated(
        uint256 indexed lastUpdatedTime,
        PerpDexLib.TokenType indexed tokenType,
        int256 indexed fundingRate,
        int256 accFeePerSize,
        int256 currentLong,
        int256 currentShort
    );

    event PositionClosed(
        uint256 indexed positionId,
        address indexed traderAddr,
        PerpDexLib.TokenType indexed tokenType,
        uint256 margin,
        uint256 size,
        uint256 initialPrice,
        bool isLong,
        uint256 finalPrice,
        int256 fundingFee
    );

    event PositionLiquidated(
        uint256 indexed positionId,
        address indexed traderAddr,
        PerpDexLib.TokenType indexed tokenType,
        uint256 margin,
        uint256 size,
        uint256 initialPrice,
        bool isLong,
        uint256 finalPrice,
        int256 fundingFee
    );

    event LimitOrderOpened(
        uint256 indexed positionId,
        address indexed traderAddr,
        PerpDexLib.TokenType indexed tokenType,
        uint256 margin,
        uint256 size,
        uint256 limitPrice,
        bool isLong,
        uint256 tpPrice,
        uint256 slPrice
    );

    event LimitOrderClosed(uint256 indexed positionId, address indexed traderAddr);

    event LimitOrderExecuted(uint256 indexed positionId, address indexed traderAddr);

    event PositionRolledBack(
        uint256 indexed positionId,
        address indexed traderAddr,
        PerpDexLib.TokenType indexed tokenType,
        uint256 margin,
        uint256 size,
        uint256 initialPrice,
        bool isLong,
        uint256 fee
    );

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function isAdmin(address[] storage adminList, address user) internal view returns (bool) {
        for (uint256 i = 0; i < adminList.length; i++) {
            if (adminList[i] == user) {
                return true;
            }
        }
        return false;
    }

    modifier onlyLiquidationAdmin() {
        if (!isAdmin(adminsByRole[PerpDexAuthLib.AdminType.Liquidation], _msgSender())) revert InvalidAdmin();
        _;
    }

    modifier onlyLimitOrderAdmin() {
        if (!isAdmin(adminsByRole[PerpDexAuthLib.AdminType.LimitOrder], _msgSender())) revert InvalidAdmin();
        _;
    }

    modifier onlyLimitOrLiquidationAdmin() {
        if (
            !isAdmin(adminsByRole[PerpDexAuthLib.AdminType.LimitOrder], _msgSender())
                && !isAdmin(adminsByRole[PerpDexAuthLib.AdminType.Liquidation], _msgSender())
        ) revert InvalidAdmin();
        _;
    }

    modifier onlySingleOpenAdmin() {
        if (!isAdmin(adminsByRole[PerpDexAuthLib.AdminType.SingleOpen], _msgSender())) revert InvalidAdmin();
        _;
    }

    modifier onlyCloseAdmin() {
        if (!isAdmin(adminsByRole[PerpDexAuthLib.AdminType.Close], _msgSender())) revert InvalidAdmin();
        _;
    }

    modifier onlyTpslAdmin() {
        if (!isAdmin(adminsByRole[PerpDexAuthLib.AdminType.Tpsl], _msgSender())) revert InvalidAdmin();
        _;
    }

    function checkZeroAddress(address _address) internal pure {
        if (_address == address(0)) revert ZeroAddress();
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    function initialize(address initialOwner) public initializer {
        checkZeroAddress(initialOwner);
        __Pausable_init();
        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();
        nextPositionId = 1;
        admin = initialOwner;
    }

    function addInitialTokenTotalSizes(uint256 count) external onlyOwner {
        PerpDexLib._addInitialTokenTotalSizes(tokenTotalSizes, count);
    }

    function changeMaxTokenTotalSizes() external onlyOwner {
        PerpDexLib._changeMaxTokenTotalSizes(tokenTotalSizes);
    }

    function setAdmin(address _admin) external onlyOwner {
        checkZeroAddress(_admin);
        admin = _admin;
    }

    function setAdmins(PerpDexAuthLib.AdminType adminType, address[] memory newAdmins) external onlyOwner {
        if (uint256(adminType) > uint256(type(PerpDexAuthLib.AdminType).max)) {
            revert InvalidAdmin();
        }
        PerpDexAuthLib._setAdmins(newAdmins, adminsByRole[adminType]);
    }

    function setOracles(address _bisonAIRouter, address _bisonAISubmission, address _pyth) external onlyOwner {
        checkZeroAddress(_bisonAIRouter);
        checkZeroAddress(_bisonAISubmission);
        checkZeroAddress(_pyth);

        bisonAIRouter = IBisonAIRouter(_bisonAIRouter);
        bisonAISubmissionProxy = IBisonAISubmissionProxy(_bisonAISubmission);
        pyth = IPyth(_pyth);
    }

    function setupAddr(address _usdt, address _lp, address _fee) external onlyOwner {
        checkZeroAddress(_usdt);
        checkZeroAddress(_lp);
        checkZeroAddress(_fee);

        require(IERC20Metadata(_usdt).decimals() == 6, "Decimal is not 6");
        externalContracts = PerpDexLib.ExternalContracts({feeContract: IFee(_fee), lp: ILP(_lp), usdt: IERC20(_usdt)});
        require(externalContracts.usdt.approve(address(externalContracts.feeContract), type(uint256).max));
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    // necessary because struct is too big
    function getPosition(uint256 positionId) external view returns (PerpDexLib.Position memory) {
        return positions[positionId];
    }

    function getOpenPositionIds() external view returns (uint256[] memory) {
        return openPositionIds;
    }

    function getLimitOrderIds() external view returns (uint256[] memory) {
        return limitOrderIds;
    }

    function getPositionIdsForTrader(address trader) external view returns (uint256[] memory) {
        return traderPositionIds[trader];
    }

    /// @dev moving method to library increases contract size by 80
    function getTraderOpenPositionIds(address trader) external view returns (PerpDexLib.TraderOpenPositionId[] memory) {
        PerpDexLib.TraderOpenPositionId[] memory traderOpenPositionIdArr =
            new PerpDexLib.TraderOpenPositionId[](uint256(type(PerpDexLib.TokenType).max) + 1);
        for (uint16 i = 0; i < traderOpenPositionIdArr.length; i++) {
            traderOpenPositionIdArr[i] = traderOpenPositionIds[trader][i];
        }
        return traderOpenPositionIdArr;
    }

    function checkUserSignedData(string memory message, bytes calldata userSignedData, address user) internal {
        PerpDexAuthLib.checkUser(message, bytes(message).length, userSignedData, user);
        traderNonce[user]++;
    }

    function openLimitOrder(PerpDexLib.OpenLimitOrderData calldata o) external onlySingleOpenAdmin whenNotPaused nonReentrant {
        checkUserSignedData(PerpDexAuthLib.getOpenLimitOrderMsg(o, traderNonce[o.trader], address(this)), o.userSignedData, o.trader);
        uint256 positionId = nextPositionId++;
        PerpDexLib._openLimitOrder(o, positionId, positions, traderPositionIds, limitOrderIds, externalContracts);
    }

    function closeLimitOrder(uint256 positionId, bytes calldata userSignedData) external onlyCloseAdmin nonReentrant {
        PerpDexLib.Position storage order = positions[positionId];
        checkUserSignedData(
            PerpDexAuthLib.getCloseLimitOrderMsg(positionId, traderNonce[order.traderAddr], address(this)), userSignedData, order.traderAddr
        );

        PerpDexLib._closeLimitOrder(order, positions, limitOrderIds, externalContracts);
    }

    function executeLimitOrders(uint256[] calldata ordersToExecute, uint64[] calldata roundIds, PerpDexLib.OraclePrices calldata priceData)
        external
        payable
        onlyLimitOrderAdmin
        whenNotPaused
        nonReentrant
    {
        if (ordersToExecute.length == 0) {
            return;
        }

        (uint256[] memory prices, uint256[] memory updatedAts) =
            PerpDexPricesLib.getPreviousPriceAndTime(roundIds, priceData, bisonAIRouter, pyth);

        for (uint256 i = 0; i < ordersToExecute.length; i++) {
            PerpDexLib.Position storage order = positions[ordersToExecute[i]];
            if (order.positionStatus != PerpDexLib.PositionStatus.LimitOrderOpen) {
                // Should not happen
                continue;
            }

            if (prices.length <= uint256(order.tokenType)) revert InvalidPriceData();
            uint256 price = prices[uint256(order.tokenType)];
            uint256 updatedAt = updatedAts[uint256(order.tokenType)];

            if (order.statusTime.limitOpenTime < updatedAt && PerpDexLib.checkExecutionForLimitOrder(order, price)) {
                PerpDexBotLib._executeLimitOrder(
                    positions,
                    ordersToExecute[i],
                    fundingFeeTokenStates,
                    traderOpenPositionIds,
                    fundingFeeGlobalState,
                    tokenTotalSizes,
                    openPositionIds,
                    externalContracts,
                    price,
                    limitOrderIds
                );
            }
        }
    }

    function openPosition(PerpDexLib.OpenPositionData calldata o) external payable onlySingleOpenAdmin whenNotPaused nonReentrant {
        checkUserSignedData(PerpDexAuthLib.getOpenPositionMsg(o, traderNonce[o.trader], address(this)), o.userSignedData, o.trader);

        uint256 positionId = nextPositionId++;
        if (positions[positionId].positionStatus != PerpDexLib.PositionStatus.Initial) revert NextPositionIdExists(); // Should not happen

        uint256 currentPrice =
            PerpDexPricesLib.submitAndGetLatestPrice(o.priceData, o.tokenType, bisonAISubmissionProxy, bisonAIRouter, pyth);

        uint256 minPrice = o.expectedPrice * 99 / 100;
        uint256 maxPrice = o.expectedPrice * 101 / 100;
        require(currentPrice >= minPrice && currentPrice <= maxPrice, "Slippage is more than 1%");

        PerpDexLib.updateFundingFeeState(
            o.tokenType, fundingFeeTokenStates[o.tokenType], fundingFeeGlobalState, tokenTotalSizes[uint256(o.tokenType)]
        );
        PerpDexLib.Position memory newPosition = PerpDexLib.createNewPosition(
            positionId,
            o,
            currentPrice,
            openPositionIds.length,
            fundingFeeTokenStates[o.tokenType].accFeePerSize,
            tokenTotalSizes,
            externalContracts.feeContract
        );

        positions[positionId] = newPosition;
        traderPositionIds[o.trader].push(positionId);
        PerpDexPricesLib.safeTransferFromAndCheckBalance(o.trader, address(this), o.marginAmount, externalContracts.usdt);

        PerpDexLib._openPosition(
            o,
            currentPrice,
            positionId,
            positions,
            fundingFeeGlobalState,
            fundingFeeTokenStates,
            traderOpenPositionIds,
            openPositionIds,
            externalContracts
        );
    }

    function rollbackPosition(uint256 positionId) external onlyOwner nonReentrant {
        PerpDexLib.Position storage position = positions[positionId];
        if (position.positionStatus != PerpDexLib.PositionStatus.Open) revert InvalidPositionStatus();
        PerpDexLib.updateFundingFeeState(
            position.tokenType,
            fundingFeeTokenStates[position.tokenType],
            fundingFeeGlobalState,
            tokenTotalSizes[uint256(position.tokenType)]
        );

        PerpDexLib.decreaseTotalPositionSize(tokenTotalSizes, position.tokenType, position.isLong, position.size);

        // Open fee is not returned
        PerpDexLib.cleanUpPosition(
            positions,
            openPositionIds,
            position.positionId,
            position.initialPrice,
            PerpDexLib.PositionStatus.RolledBack,
            traderOpenPositionIds[position.traderAddr][uint16(position.tokenType)]
        );
        PerpDexPricesLib.safeTransferAndCheckBalance(position.traderAddr, position.margin, externalContracts.usdt);
        emit PerpDex.PositionRolledBack(
            position.positionId,
            position.traderAddr,
            position.tokenType,
            position.margin,
            position.size,
            position.initialPrice,
            position.isLong,
            position.closeFee
        );
    }

    function tpslClosePositions(uint256[] calldata positionsToClose, uint64[] calldata roundIds, PerpDexLib.OraclePrices calldata priceData)
        external
        payable
        onlyTpslAdmin
        whenNotPaused
        nonReentrant
    {
        if (positionsToClose.length == 0) {
            return;
        }

        (uint256[] memory prices, uint256[] memory updatedAts) =
            PerpDexPricesLib.getPreviousPriceAndTime(roundIds, priceData, bisonAIRouter, pyth);

        for (uint256 i = 0; i < positionsToClose.length; i++) {
            PerpDexLib.Position storage position = positions[positionsToClose[i]];
            if (position.positionStatus != PerpDexLib.PositionStatus.Open) {
                // Should not happen
                continue;
            }

            if (prices.length <= uint256(position.tokenType)) revert InvalidPriceData();
            uint256 price = prices[uint256(position.tokenType)];
            uint256 updatedAt = updatedAts[uint256(position.tokenType)];

            PerpDexBotLib._tpslClosePosition(
                positions,
                positionsToClose[i],
                fundingFeeTokenStates,
                traderOpenPositionIds,
                fundingFeeGlobalState,
                tokenTotalSizes,
                openPositionIds,
                externalContracts,
                price,
                updatedAt
            );
        }
    }

    function closePosition(uint256 positionId, PerpDexLib.OraclePrices calldata priceData, bytes calldata userSignedData)
        external
        payable
        onlyCloseAdmin
        whenNotPaused
        nonReentrant
    {
        PerpDexLib.Position storage position = positions[positionId];

        checkUserSignedData(
            PerpDexAuthLib.getClosePositionMsg(positionId, traderNonce[position.traderAddr], address(this)),
            userSignedData,
            position.traderAddr
        );

        uint256 currentPrice =
            PerpDexPricesLib.submitAndGetLatestPrice(priceData, position.tokenType, bisonAISubmissionProxy, bisonAIRouter, pyth);

        PerpDexLib._closePosition(
            positions,
            positionId,
            fundingFeeTokenStates[position.tokenType],
            fundingFeeGlobalState,
            traderOpenPositionIds,
            tokenTotalSizes,
            openPositionIds,
            currentPrice,
            externalContracts
        );
    }

    function liquidatePositions(
        uint256[] calldata liquidatablePositions,
        uint64[] calldata roundIds,
        PerpDexLib.OraclePrices calldata priceData
    ) external payable onlyLiquidationAdmin whenNotPaused nonReentrant {
        if (liquidatablePositions.length == 0) {
            return;
        }

        (uint256[] memory prices, uint256[] memory updatedAts) =
            PerpDexPricesLib.getPreviousPriceAndTime(roundIds, priceData, bisonAIRouter, pyth);

        for (uint256 i = 0; i < liquidatablePositions.length; i++) {
            PerpDexLib.Position storage position = positions[liquidatablePositions[i]];
            if (position.positionStatus != PerpDexLib.PositionStatus.Open) {
                // Should not happen
                continue;
            }

            if (prices.length <= uint256(position.tokenType)) revert InvalidPriceData();
            uint256 price = prices[uint256(position.tokenType)];
            uint256 safeUpdatedAt =
                updatedAts[uint256(position.tokenType)] - (priceData.oracleType == PerpDexLib.OracleType.BisonAI ? 10 : 0); // dataFreshness = 10

            if (position.statusTime.openTime < safeUpdatedAt && position.marginUpdatedTime < safeUpdatedAt) {
                PerpDexBotLib._liquidatePosition(
                    positions,
                    liquidatablePositions[i],
                    fundingFeeTokenStates,
                    traderOpenPositionIds,
                    fundingFeeGlobalState,
                    tokenTotalSizes,
                    openPositionIds,
                    externalContracts,
                    price
                );
            }
        }
    }

    function setTpslPrice(uint256 id, uint256 tpPrice, uint256 slPrice, bytes calldata userSignedData)
        external
        onlyTpslAdmin
        whenNotPaused
        nonReentrant
    {
        PerpDexLib.Position storage position = positions[id];
        checkUserSignedData(
            PerpDexAuthLib.getSetTpslMsg(id, tpPrice, slPrice, traderNonce[position.traderAddr], address(this)),
            userSignedData,
            position.traderAddr
        );

        PerpDexLib._setTpslPrice(position, tpPrice, slPrice);
    }

    function submitAndGetBisonAIRoundId(PerpDexLib.OraclePrices calldata priceData) external onlyLimitOrLiquidationAdmin nonReentrant {
        PerpDexPricesLib.submitAndGetBisonAIRoundId(priceData, bisonAISubmissionProxy, bisonAIRouter);
    }

    function changeMargin(
        uint256 positionId,
        bool addMargin,
        uint256 marginDelta,
        PerpDexLib.OraclePrices calldata priceData,
        bytes calldata userSignedData
    ) external onlySingleOpenAdmin whenNotPaused nonReentrant {
        PerpDexLib.Position storage position = positions[positionId];
        checkUserSignedData(
            PerpDexAuthLib.getChangeMarginMsg(positionId, addMargin, marginDelta, traderNonce[position.traderAddr], address(this)),
            userSignedData,
            position.traderAddr
        );

        uint256 currentPrice =
            PerpDexPricesLib.submitAndGetLatestPrice(priceData, position.tokenType, bisonAISubmissionProxy, bisonAIRouter, pyth);

        PerpDexLib._changeMargin(
            position,
            fundingFeeTokenStates[position.tokenType],
            fundingFeeGlobalState,
            tokenTotalSizes[uint256(position.tokenType)],
            addMargin,
            marginDelta,
            currentPrice,
            externalContracts
        );
    }

    function claimProtocolFundingFee() external nonReentrant {
        if (msg.sender != admin) revert InvalidAdmin();
        if (fundingFeeGlobalState.protocolClaimable <= 0) revert InvalidProtocolClaimable();
        if (fundingFeeGlobalState.protocolClaimable > externalContracts.usdt.balanceOf(address(this))) revert InvalidProtocolClaimable();
        PerpDexPricesLib.safeTransferAndCheckBalance(admin, fundingFeeGlobalState.protocolClaimable, externalContracts.usdt);
    }

    function depositFundingFeeGlobalStateBalance(uint256 balance) external nonReentrant {
        if (msg.sender != admin) revert InvalidAdmin();
        PerpDexPricesLib.safeTransferFromAndCheckBalance(admin, address(this), balance, externalContracts.usdt);
        fundingFeeGlobalState.bufferBalance += balance;
    }

    function updateFundingFeeStates() external onlyOwner nonReentrant {
        uint256 tokenCount = 19;
        for (uint256 i; i < tokenCount; i++) {
            PerpDexLib.updateFundingFeeState(
                PerpDexLib.TokenType(i),
                fundingFeeTokenStates[PerpDexLib.TokenType(i)],
                fundingFeeGlobalState,
                tokenTotalSizes[uint256(PerpDexLib.TokenType(i))]
            );
        }
    }
}
