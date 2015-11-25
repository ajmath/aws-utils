#!/usr/bin/env python

import argparse
import os
import sys
import boto
import ConfigParser

parser = argparse.ArgumentParser(description='Get AWS STS credentials')

parser.add_argument("-f", "--force-new",
  help="Should existing valid keys be reissued?", action="store_true")
parser.add_argument("-d", "--duration", metavar="DURATION",
  help="Duration of STS credentials. Defaults to 12 hours", type=int, default=43200)
parser.add_argument('profile', metavar='AWS_PROFILE_NAME',
  help='AWS profile name')
parser.add_argument('accountId', metavar='AWS_ACCOUNT_ID',
  help='AWS account id')
parser.add_argument('userName', metavar='AWS_USER',
  help='AWS IAM User Name')
parser.add_argument('mfaToken', metavar='MFA_TOKEN',
  help='leave this blank to reset keys to default', nargs="?")

args = parser.parse_args()

def log(str):
  sys.stderr.write(str + "\n")

def profile_section():
  return 'profile ' + args.profile

def config_file_name(name):
  return "{0}/.aws/{1}".format(os.environ['HOME'], name)

def load_config(file_name):
  if not os.path.exists(config_file_name(file_name)):
    return None
  config = ConfigParser.ConfigParser()
  config.read(config_file_name(file_name))
  return config

def load_keys(file_name):
  config = load_config(file_name)
  if config == None:
    return None
  profileConfig = {}
  try:
    options = config.options(profile_section())
    for option in options:
      profileConfig[option] = config.get(profile_section(), option)
    return profileConfig
  except:
    return None

def update_config_section(config, keys):
  config.remove_section(profile_section())
  config.add_section(profile_section())
  for key, value in keys.iteritems():
    config.set(profile_section(), key, value)

def update_credentials(new_keys):
  config = load_config("config")
  update_config_section(config, new_keys)
  config.write(open(config_file_name("config"), "w"))

def copy_defaults():
  keys = load_keys("config")
  config = ConfigParser.ConfigParser()
  update_config_section(config, keys)
  config.write(open(config_file_name(args.profile + ".credentials"), "w"))
  return keys

def print_exports(keys = {}):
  print_export_values(keys.get("region", ""), keys.get("aws_access_key_id",""),
    keys.get("aws_secret_access_key",""), keys.get("aws_session_token",""))

def print_export_values(region = "", accessKey = "", secretKey = "", session = ""):
  sys.stdout.write("export AWS_DEFAULT_REGION=%s\n" % region)
  sys.stdout.write("export AWS_ACCESS_KEY_ID=%s\n" % accessKey)
  sys.stdout.write("export AWS_ACCESS_KEY=%s\n" % accessKey)
  sys.stdout.write("export AWS_SECRET_ACCESS_KEY=%s\n" % secretKey)
  sys.stdout.write("export AWS_SECRET_KEY=%s\n" % secretKey)
  sys.stdout.write("export AWS_SESSION_TOKEN=%s\n" % session)

def valid_sts_keys(keys):
  if "aws_session_token" not in keys:
    return False
  from boto.vpc import VPCConnection
  conn = VPCConnection(
    aws_access_key_id=keys["aws_access_key_id"],
    aws_secret_access_key=keys["aws_secret_access_key"],
    security_token=keys["aws_session_token"])
  try:
    conn.get_all_vpcs
    return True
  except:
    return False

def get_sts_keys(default_keys):
  from boto.sts import STSConnection
  baseline_keys = load_keys(args.profile + ".credentials")
  conn = STSConnection(default_keys["aws_access_key_id"], default_keys["aws_secret_access_key"])
  mfaArn = "arn:aws:iam::{0}:mfa/{1}".format(args.accountId, args.userName)
  log("mfa device = %s" % mfaArn)
  try:
    creds = conn.get_session_token(args.duration, args.force_new, mfaArn, args.mfaToken)
    log("Session will expire at %s" % creds.expiration)
    return {
      "aws_access_key_id": creds.access_key,
      "aws_secret_access_key": creds.secret_key,
      "aws_session_token": creds.session_token
    }
  except boto.exception.BotoServerError, e:
    if "MultiFactorAuthentication failed" in str(e):
      log("Invalid MFA token, resetting default keys")
      return default_keys
    elif "InvalidClientTokenId" in str(e):
      log("Invalid default credentials")
      return None
    else:
      raise e

def main():
  existing_keys = load_keys("config")
  if not existing_keys:
    log("No keys found for profile {0} in {1}, have you ran 'aws configure'?"
      .format(args.profile, config_file_name("config")))
    sys.exit(1)

  default_keys = load_keys(args.profile + ".credentials")
  if default_keys == None:
    default_keys = copy_defaults()

  pending_keys = {}
  if args.mfaToken == None:
    log("No MFA token present so keys were reset to defaults")
    pending_keys = default_keys
  elif valid_sts_keys(existing_keys) and not args.force_new:
    log("Exising STS keys are still valid and will not be updated")
    pending_keys = existing_keys
  else:
    log("Fetching new STS keys")
    pending_keys = get_sts_keys(default_keys)
    if pending_keys == None:
      sys.exit(1)

  new_keys = existing_keys.copy()
  new_keys.pop("aws_session_token", None)
  new_keys.update(pending_keys)
  update_credentials(new_keys)

  print_exports(new_keys)

main()
