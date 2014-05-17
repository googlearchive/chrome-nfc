/*
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 *     http://www.apache.org/licenses/LICENSE-2.0
  
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * @fileoverview Tag() class
 */


/*
 * Unfortunately, some tags, such as Ultralight-*, require async read
 * to distiguish the tag type. The 'cb' will be called if the order matters.
 */
function Tag(tag_name, tag_id) {
  switch (tag_name) {
  case "tt2":
    return new TT2(tag_id);

  case "mifare_classic":
    return new MifareClassic(tag_id);
  }

  return null;
}

