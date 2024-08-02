# W3recovery

W3recovery is a web3 crypto wallet recovery tool which may help you to recover your crypto wallet. This project is experimental and was written for contest.

## How do I run the script?

First you need to [download python](https://www.python.org/downloads/) and install requirements with pip:
```sh
pip install -r requirements.txt
```

> **NOTE**: This project requires Python 3.7 or higher.

If you don't have OpenCL installed, then you need to install it from your GPU vendor. If you want to use CPU bruteforce only, then you need to install OpenCL anyway. You can download Intel OpenCL runtime (also works for AMD processors) [here](https://www.intel.com/content/www/us/en/developer/articles/tool/opencl-drivers.html), then you simply run the following command:
```sh
python3 main.py
```

If you want to provide more passwords to check, then you can create a `.txt` file and place every password you want to check on the new line, after that you simply pass the path to the file as an argument using `-p` option. For example let's say the file called passwords.txt and placed in the script's folder, then the command will look like this:
```sh
python3 main.py -p passwords.txt
```

> **NOTE**: All the passwords are checked only once for a wallet.

## How it works?

The tool tries to collect your passwords from different sources, including chromium browsers. Then it tries to collect wallets and use collected passwords to crack the wallets. If match found, then wallet is decrypted and wallet data is dumped to the output file.

> **NOTE**: It may take some time to bruteforce the wallets. If you have good GPU, then it should be quick. If GPU cannot be used for whatever reason, the tool will fallback to the CPU. It also may take some CPU time to build and optimize OpenCL kernels. If you don't have OpenCL installed, then once again you must install it from your GPU vendor. If you encounter an issue while bruteforcing and want to try again, then you can delete cache.db file.

## Which wallets are supported?

For now the following wallets are supported:

* MetaMask-like wallets (MetaMask, Ronin, Binance Chain, etc.)
* Brave Wallet
* Trust Wallet (requires good GPU to perform GPU bruteforce)

### So little?

The project is in early stage of development. It wasn't written to provide full-featured password recovery tool, instead it is written for a competition. These wallets were implemented first as they are the most popular, however more wallets may be added in the future (if the project will be popular enough).

## Which platforms are supported?

The project is in early stage of development. For now only **windows** and **linux** platforms are supported. More platforms may be added in the future.

This project was tested with following configurations:

* **Windows 10 x64** + **Python 3.11 x64**
* **Ubuntu 20.04 LTS** + **Python 3.11 x64**

## License

Licensed under MIT license unless stated otherwise. This is competition project so I do not accept any issues nor pull requests (at least now). If you need to fix something, then make a fork and do it yourself, the code is open source.
