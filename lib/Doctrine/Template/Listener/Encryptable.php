<?php
/*
 *  $Id$
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This software consists of voluntary contributions made by many individuals
 * and is licensed under the LGPL. For more information, see
 * <http://www.phpdoctrine.org>.
 */

/**
 * Listener for the Encryptable behavior which automatically sets the salt
 * and encrypts configured columns when a record is inserted and updated.
 *
 * @package     Doctrine
 * @subpackage  Template
 * @license     http://www.opensource.org/licenses/lgpl-license.php LGPL
 * @link        www.phpdoctrine.org
 * @since       1.2
 * @version     $Revision$
 * @author      Tim Schofield <tim@scoffer.net>
 */
class Doctrine_Template_Listener_Encryptable extends Doctrine_Record_Listener
{
    /**
     * Array of Encryptable options
     *
     * @var string
     */
    protected $_options = array();
    
    /**
     * __construct
     *
     * @param string $options 
     * @return void
     */
    public function __construct(array $options)
    {
        $this->_options = $options;
    }

    /**
     * Create and populate the salt column when a record is inserted
     * TODO Check column is a string column and is correct size for encrypted field
     * TODO Restrict Salt colum to 13 or 26 for uniqid
     * @param Doctrine_Event $event
     * @return void
     */
    public function preInsert(Doctrine_Event $event)
    {
        $record = $event->getInvoker();
        if ( ! $this->_options['columns']['salt']['disabled']) {
            $saltName = $record->getTable()->getFieldName($this->_options['columns']['salt']['name']);
            $modified = $record->getModified();
            if ( ! isset($modified[$saltName])) {
                $record->$saltName = uniqid("");
            }
        }
    
        if ($this->_options['encrypted_columns']){
            $modified = $record->getModified();
            foreach ($this->_options['encrypted_columns'] as $column) {
                $fieldName = $record->getTable()->getFieldName($column);
                if (isset($modified[$fieldName])) {
                    $record->$column = $this->encrypt($record->$column,$record->$saltName);
                }
            }
        }
    }
    
    /**
     * Encrypts configured column(s) when a record is updated
     *
     * @param Doctrine_Event $event
     * @return void
     */
    public function preUpdate(Doctrine_Event $event)
    {
        $record = $event->getInvoker();
        $saltDisabled = $this->_options['columns']['salt']['disabled'];
        if ( ! $saltDisabled) {
            $saltName = $record->getTable()->getFieldName($this->_options['columns']['salt']['name']);
        }
        foreach ($this->_options['encrypted_columns'] as $column) {
            $record->$column = $this->encrypt($record->$column,$record->$saltName);
        }
    }
    
    /**
     * Decrypt encryptable column(s) when a record is retreived
     *
     * @param Doctrine_Event $event
     * @return void
     */
    public function preHydrate(Doctrine_Event $event)
    {
        $data = $event->data;
        foreach ($this->_options['encrypted_columns'] as $column) {
            $data[$column] = $this->decrypt($data[$column],$data['salt']);
        }        
        $event->data = $data;
    }

    /**
     * Encrypt function
     *
     * @param String $text
     * @param String $salt
     * @return String
     */
    protected function encrypt($text,$salt=NULL) 
    { 
        $secret = $this->_options['secret'];
        $secureKey = hash('sha256',$salt . $secret ,TRUE);
        $mode= MCRYPT_MODE_ECB;
        $cipher = MCRYPT_RIJNDAEL_256;
        $ivSize = mcrypt_get_iv_size($cipher, $mode);
        $iv = mcrypt_create_iv($ivSize , MCRYPT_RAND);
        return base64_encode(mcrypt_encrypt($cipher, $secureKey, $text, $mode, $iv)); 
    } 

    /**
     * Decrypt function
     *
     * @param String $text
     * @param String $salt
     * @return String
     */
    protected function decrypt($text,$salt=NULL)
    { 
        $secret = $this->_options['secret'];
        $secureKey = hash('sha256',$salt . $secret ,TRUE);
        $mode= MCRYPT_MODE_ECB;
        $cipher = MCRYPT_RIJNDAEL_256;
        $ivSize = mcrypt_get_iv_size($cipher, $mode);
        $iv = mcrypt_create_iv($ivSize , MCRYPT_RAND);
        return trim(mcrypt_decrypt($cipher, $secureKey, base64_decode($text), $mode, $iv)); 
    }     
}
