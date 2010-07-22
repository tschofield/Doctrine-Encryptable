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
 * Doctrine_Template_Encryptable
 *
 * Encryptable behavior which automatically sets the salt
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
class Doctrine_Template_Encryptable extends Doctrine_Template
{
    /**
     * Array of Encryptable options
     *
     * @var string
     */
    protected $_options = array('listener'              => 'Doctrine_Template_Listener_Encryptable',
                                'default'               => false,
                                'params'                => array(),
                                'columns'                  => array('salt' =>  array('name'          =>  'salt',
                                                                                   'alias'         =>  null,
                                                                                  'type'          =>  'string',
                                                                                  'length'        =>  13,
                                                                                  'disabled'      =>  false,
                                                                                  'options'       =>  array('notnull' => true,)
                                                                                 )    
                                                                ),
                                'encrypted_columns'        => array(),
                                'secret'                => array(),
                               );
    

    /**
     * __construct
     *
     * @param array $options
     * @return void
     */
    public function __construct(array $options = array())
    {
        if (!class_exists($this->_options['listener'], true)) {
            throw new Exception('Class: ' . $this->_options['listener'] . ' not found');
        }
        
        parent::__construct($options);
    }
    
    /**
     * Set table definition for Encryptable behavior
     *
     * @return void
     */
    public function setTableDefinition()
    {
        if( ! $this->_options['columns']['salt']['disabled']) {
            $name = $this->_options['columns']['salt']['name'];
            if ($this->_options['columns']['salt']['alias']) {
                $name .= ' as ' . $this->_options['columns']['salt']['alias'];
            }
            $this->hasColumn($name, $this->_options['columns']['salt']['type'],
                             $this->_options['columns']['salt']['length'],
                             $this->_options['columns']['salt']['options']);
        }


        $listener = new $this->_options['listener']($this->_options);
        
        if (get_class($listener) !== 'Doctrine_Template_Listener_Encryptable' && 
            !is_subclass_of($listener, 'Doctrine_Template_Listener_Encryptable')) {
                throw new Exception('Invalid listener. Must be Doctrine_Template_Listener_Encryptable or subclass');
        }
        $this->addListener($listener, 'Encryptable');
    }
}
